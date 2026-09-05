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

- Matching: `bd_meta_info` (5.15+) / `bd_part->info` (5.10)
- LSM add: name-style (≤6.6) / `lsm_id`+`LSM_ID_UNDEF` (6.8+)
- Registration: `.name`-style everywhere

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
