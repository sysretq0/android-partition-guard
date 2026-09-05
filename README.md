# Partition Guard

Data-driven LSM guarding per-device partitions (NVRAM identity, persist, EFS)
against writes from Android userspace. For GKI kernels 5.10+.

## Scope discipline

Protected **only** if both hold:

1. **Per-device unique** — NVRAM identity, calibration, persist data, EFS
2. **Never written by OTAs, fastboot, or recovery**

| Protected | Why |
|---|---|
| MTK `nvram` `nvdata` `nvcfg` `protect1` `protect2` `seccfg` | NVRAM identity (IMEI, MAC, calibration) |
| QCOM `modemst1` `modemst2` `fsg` `fsc` | EFS |
| Samsung `efs` | EFS |
| `persist` (all) | per-device store |

**Deliberately excluded:** `boot`, `recovery`, modem firmware (`modem*`),
`super`/`system`/`vendor` — anything an OTA or flashing flow legitimately
writes. Flashing and OTAs can never be blocked by this LSM. There is
intentionally no boot-partition option (cf. the foot-gun in other guards).

## How it works

- Matches GPT partition labels (`volname`) against a runtime list
- Hooks: `file_open` (write) + `file_ioctl`/`file_ioctl_compat`
  (`BLKDISCARD`/`BLKSECDISCARD`/`BLKZEROOUT`) on block devices
- `setattr` deliberately **not** hooked (node ownership belongs to ueventd;
  no data destruction possible through it)
- Deny = `-EPERM` + ratelimited log. No panics, no silent remounts.

## Configuration (nothing hardcoded beyond replaceable defaults)

Kernel cmdline:

- `partition_guard.protect=a,b,c` — replace the default list
- `partition_guard.extend=a,b` — append to it
- `partition_guard.disable` — off switch

Sysfs (`/sys/kernel/partition_guard/`): `enabled` (rw), `protected` (ro),
`add`/`remove` (wo).

## Threat model (honest version)

- Stops: buggy scripts, reckless apps, malware that writes named
  partitions without knowing about the guard. Deny is fail-closed on
  identified partitions.
- Fail-open where it cannot identify: whole-disk opens and non-GPT
  devices are allowed (it only judges what it can name).
- NOT a boundary against root: root can `echo 0 > enabled`, remove
  names, or boot with `partition_guard.disable`. Same honesty as
  SELinux permissive — this is a guardrail, not a cage.
- No protection against fastboot/recovery writes (different kernel)
  — which is also why flashing can never break.

## Install

```sh
cd <repo-sync root>   # dir containing common/
sh partition-guard/kernel/setup.sh [<commit-or-tag>]
```

Full clone is kept (pinning/versioning). Symlinks
`security/partition-guard`, hooks `security/Makefile` + `security/Kconfig`
(idempotent), appends to the LSM default list (verified). Then enable
`CONFIG_PARTITION_GUARD=y` (default once integrated) and build.

## Version support

- Matching: ref-pinned `dev_t` resolution — `blkdev_get_no_open`
  (5.11+) / `get_gendisk`+`disk_get_part` (5.10). The cached bdev
  pointer is never trusted: rescan frees it with direct kfree, so the
  lookup holds a reference (see `tests/race-fuzz.sh`). The helpers are
  the *no-open* variants on purpose — openers would re-enter our own
  `file_open` hook.
- LSM add: name-style (≤6.6) / `lsm_id`+`LSM_ID_UNDEF` (6.8+)
- Registration: `device_initcall` everywhere (`security_initcall`
  exists on none of our trees; ordered `DEFINE_LSM` dispatch silently
  skipped 5.10)

## Testing

`tests/race-fuzz.sh` storms write-opens and `BLKDISCARD` on a protected
node while storming `BLKRRPART` on its LUN, then asserts the `denied`
counter climbed and KASAN stayed quiet. Targets resolve through
`/dev/block/by-name` (`LABEL=nvram` suffices). See `tests/TESTING.md`
for the KASAN build inputs and exit codes.

## Inspiration

[Baseband Guard](https://github.com/vc-teahouse/Baseband-guard) by
showdo — the hook points (open-write, destructive ioctls), the
installer shape (clone, symlink, Makefile/Kconfig hooks), and the LSM-list
activation all follow its lead. Partition Guard differs deliberately:
data-driven list instead of hardcoded partitions, NVRAM/persist/EFS scope
instead of everything (no boot/recovery option to foot-gun with), no
setattr hook, no legacy-kernel selinux patching.

## License

GPL-2.0-only. See LICENSE.
