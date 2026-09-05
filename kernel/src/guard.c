// SPDX-License-Identifier: GPL-2.0
/*
 * Partition Guard - data-driven LSM protecting per-device partitions.
 *
 * Inspired by Baseband Guard (vc-teahouse, showdo): hook points,
 * installer shape, and LSM activation follow its lead; the list,
 * scope, and compat approach are our own.
 *
 * Scope discipline: ONLY partitions that are (a) per-device unique
 * (NVRAM identity, persist, EFS) and (b) never written by OTAs, fastboot,
 * or recovery. Boot, recovery, modem firmware and super are deliberately
 * NOT covered, so flashing and OTA flows can never be blocked by this LSM.
 *
 * Matching is done on GPT partition labels (volname) against a runtime
 * list: compiled-in defaults, replaceable/extensible via kernel cmdline
 * and sysfs. Nothing is hardcoded beyond replaceable defaults.
 *
 * Covered hooks: open-for-write and destructive ioctls (discard/zeroout)
 * on block devices. chmod/chown (setattr) is deliberately NOT hooked:
 * node ownership is managed by ueventd at boot and data cannot be
 * destroyed through it.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
#include <linux/genhd.h>
#endif
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#include <uapi/linux/lsm.h>
#endif

#define GUARD_MAX_NAMES	64
#define GUARD_NAME_LEN	64

static const char * const guard_defaults[] = {
	/* MTK NVRAM identity */
	"nvram", "nvdata", "nvcfg", "protect1", "protect2", "seccfg",
	/* Qualcomm EFS */
	"modemst1", "modemst2", "fsg", "fsc",
	/* Samsung EFS */
	"efs",
	/* universal per-device store */
	"persist",
};

static char guard_names[GUARD_MAX_NAMES][GUARD_NAME_LEN];
static unsigned int guard_count;
static bool guard_enabled = true;
static bool guard_cmdline_touched;
static DEFINE_SPINLOCK(guard_lock);

static void guard_strip(char *name)
{
	size_t len = strlen(name);

	while (len > 0 && (name[len - 1] == '\n' ||
			name[len - 1] == ' ' || name[len - 1] == '\t'))
		name[--len] = '\0';
}

static void guard_add_one(const char *name)
{
	size_t len;
	unsigned int i;
	unsigned long flags;

	if (!name)
		return;
	while (*name == ',' || *name == ' ')
		name++;
	guard_strip((char *)name);
	len = strnlen(name, GUARD_NAME_LEN);
	if (len == 0 || len >= GUARD_NAME_LEN)
		return;

	spin_lock_irqsave(&guard_lock, flags);
	for (i = 0; i < guard_count; i++) {
		if (!strncmp(guard_names[i], name, GUARD_NAME_LEN))
			goto out;
	}
	if (guard_count < GUARD_MAX_NAMES) {
		memcpy(guard_names[guard_count], name, len);
		guard_names[guard_count][len] = '\0';
		guard_count++;
	} else {
		pr_warn("partition-guard: list full, ignoring '%s'\n", name);
	}
out:
	spin_unlock_irqrestore(&guard_lock, flags);
}

static void guard_del_one(const char *name)
{
	size_t len;
	unsigned int i;
	unsigned long flags;

	if (!name)
		return;
	while (*name == ',' || *name == ' ')
		name++;
	guard_strip((char *)name);
	len = strnlen(name, GUARD_NAME_LEN);
	if (len == 0 || len >= GUARD_NAME_LEN)
		return;

	spin_lock_irqsave(&guard_lock, flags);
	for (i = 0; i < guard_count; i++) {
		if (!strncmp(guard_names[i], name, GUARD_NAME_LEN)) {
			memmove(&guard_names[i], &guard_names[i + 1],
				(guard_count - i - 1) * GUARD_NAME_LEN);
			memset(&guard_names[guard_count - 1], 0, GUARD_NAME_LEN);
			guard_count--;
			break;
		}
	}
	spin_unlock_irqrestore(&guard_lock, flags);
}

static void guard_load_defaults(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(guard_defaults); i++)
		guard_add_one(guard_defaults[i]);
}

static int __init guard_opt_protect(char *str)
{
	char *tok;

	guard_cmdline_touched = true;
	/* replace: clear first (init runs after parsing, adds defaults
	 * only when untouched) */
	guard_count = 0;
	memset(guard_names, 0, sizeof(guard_names));
	while ((tok = strsep(&str, ",")) != NULL)
		guard_add_one(tok);
	return 0;
}
__setup("partition_guard.protect=", guard_opt_protect);

static int __init guard_opt_extend(char *str)
{
	char *tok;

	guard_cmdline_touched = true;
	while ((tok = strsep(&str, ",")) != NULL)
		guard_add_one(tok);
	return 0;
}
__setup("partition_guard.extend=", guard_opt_extend);

static int __init guard_opt_disable(char *str)
{
	guard_enabled = false;
	pr_info("partition-guard: disabled via cmdline\n");
	return 0;
}
__setup("partition_guard.disable", guard_opt_disable);

static bool guard_protected_bdev(struct block_device *bdev)
{
	const u8 *volname = NULL;
	unsigned int i;
	bool hit = false;
	unsigned long flags;

	if (!READ_ONCE(guard_enabled))
		return false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (bdev->bd_meta_info)
		volname = bdev->bd_meta_info->volname;
#else
	if (bdev->bd_part && bdev->bd_part->info)
		volname = bdev->bd_part->info->volname;
#endif
	if (!volname || !volname[0])
		return false;

	spin_lock_irqsave(&guard_lock, flags);
	for (i = 0; i < guard_count; i++) {
		if (guard_names[i][0] &&
		    !strncmp(guard_names[i], volname, GUARD_NAME_LEN)) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&guard_lock, flags);
	return hit;
}

static int guard_file_open(struct file *file)
{
	struct inode *inode = file_inode(file);

	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	if (!S_ISBLK(inode->i_mode))
		return 0;
	if (!guard_protected_bdev(I_BDEV(inode)))
		return 0;
	pr_warn_ratelimited("partition-guard: denied write open on protected partition (dev %u:%u)\n",
			    MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
	return -EPERM;
}

static int guard_deny_ioctl(struct file *file, unsigned int cmd)
{
	struct inode *inode = file_inode(file);

	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
		break;
	default:
		return 0;
	}
	if (!S_ISBLK(inode->i_mode))
		return 0;
	if (!guard_protected_bdev(I_BDEV(inode)))
		return 0;
	pr_warn_ratelimited("partition-guard: denied destructive ioctl %u on protected partition (dev %u:%u)\n",
			    cmd, MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
	return -EPERM;
}

static int guard_file_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	return guard_deny_ioctl(file, cmd);
}

static int guard_file_ioctl_compat(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	return guard_deny_ioctl(file, cmd);
}

static ssize_t guard_enabled_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", guard_enabled ? 1 : 0);
}

static ssize_t guard_enabled_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned long flags;

	spin_lock_irqsave(&guard_lock, flags);
	WRITE_ONCE(guard_enabled, (buf[0] == '1'));
	spin_unlock_irqrestore(&guard_lock, flags);
	return count;
}

static ssize_t guard_protected_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	unsigned int i, len = 0;
	unsigned long flags;

	spin_lock_irqsave(&guard_lock, flags);
	for (i = 0; i < guard_count; i++) {
		if (len + GUARD_NAME_LEN >= PAGE_SIZE)
			break;
		len += scnprintf(buf + len, PAGE_SIZE - len, "%s\n",
				 guard_names[i]);
	}
	spin_unlock_irqrestore(&guard_lock, flags);
	return len;
}

static ssize_t guard_add_store(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	char name[GUARD_NAME_LEN];
	size_t len = min(count, (size_t)(GUARD_NAME_LEN - 1));

	memcpy(name, buf, len);
	name[len] = '\0';
	guard_add_one(name);
	return count;
}

static ssize_t guard_remove_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	char name[GUARD_NAME_LEN];
	size_t len = min(count, (size_t)(GUARD_NAME_LEN - 1));

	memcpy(name, buf, len);
	name[len] = '\0';
	guard_del_one(name);
	return count;
}

static struct kobj_attribute guard_enabled_attr =
	__ATTR(enabled, 0644, guard_enabled_show, guard_enabled_store);
static struct kobj_attribute guard_protected_attr =
	__ATTR(protected, 0444, guard_protected_show, NULL);
static struct kobj_attribute guard_add_attr =
	__ATTR(add, 0200, NULL, guard_add_store);
static struct kobj_attribute guard_remove_attr =
	__ATTR(remove, 0200, NULL, guard_remove_store);

static struct attribute *guard_attrs[] = {
	&guard_enabled_attr.attr,
	&guard_protected_attr.attr,
	&guard_add_attr.attr,
	&guard_remove_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(guard);

static struct security_hook_list guard_hooks[] = {
	LSM_HOOK_INIT(file_open, guard_file_open),
	LSM_HOOK_INIT(file_ioctl, guard_file_ioctl),
	LSM_HOOK_INIT(file_ioctl_compat, guard_file_ioctl_compat),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static struct lsm_id guard_lsmid = {
	.name = "partition_guard",
	.id = LSM_ID_UNDEF,
};

static void guard_add_hooks(void)
{
	security_add_hooks(guard_hooks, ARRAY_SIZE(guard_hooks), &guard_lsmid);
}
#else
static void guard_add_hooks(void)
{
	security_add_hooks(guard_hooks, ARRAY_SIZE(guard_hooks),
			   "partition_guard");
}
#endif

static int __init guard_init(void)
{
	struct kobject *kobj;

	if (!guard_cmdline_touched)
		guard_load_defaults();

	kobj = kobject_create_and_add("partition_guard", kernel_kobj);
	if (!kobj) {
		pr_warn("partition-guard: sysfs unavailable, continuing\n");
	} else if (sysfs_create_groups(kobj, guard_groups)) {
		pr_warn("partition-guard: sysfs groups failed, continuing\n");
		kobject_put(kobj);
	}

	guard_add_hooks();
	pr_info("partition-guard: active, %u partitions protected\n",
		guard_count);
	return 0;
}

DEFINE_LSM(partition_guard) = {
	.name = "partition_guard",
	.init = guard_init,
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sysretq0");
MODULE_DESCRIPTION("Data-driven LSM guard for per-device partitions");
