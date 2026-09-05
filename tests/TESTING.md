# Testing Partition Guard

Two layers: functional smoke (does it deny?) and the race fuzz (is the
lookup itself sound under a concurrent partition-table rescan?).

## KASAN test kernel (builder repo)

One artifacts-only run, 5.10 shown — fragments off to isolate the guard:

```sh
gh workflow run build-kernel.yml --ref main \
  -f branch=android12-5.10-stable \
  -f ksu=true -f nomount=true -f guard=true \
  -f fragments=false -f release=false \
  -f extra_config='CONFIG_KASAN=y,CONFIG_KASAN_GENERIC=y'
```

Flash the resulting AnyKernel3 zip, boot, confirm the guard is alive:

```sh
cat /sys/kernel/partition_guard/enabled      # 1
cat /sys/kernel/partition_guard/protected    # nvram, persist, ...
```

## Smoke (any kernel with the guard)

```sh
# writes nothing (count=0) — the write-OPEN itself must die:
dd if=/dev/zero of=/dev/block/sdc35 bs=512 count=0   # expect: Permission denied
cat /sys/kernel/partition_guard/denied               # climbs by 1
```

## Race fuzz (KASAN kernel only)

```sh
adb push tests/race-fuzz.sh /data/local/tmp/
# by-name resolution is automatic; LABEL alone picks the target:
adb shell 'LABEL=nvram DUR=60 sh /data/local/tmp/race-fuzz.sh'
# unusual layout? override explicitly:
# adb shell 'PART=/dev/block/sdc35 DISK=/dev/block/sdc LABEL=nvram sh /data/local/tmp/race-fuzz.sh'
```

What it does: storms `open(O_WRONLY)` then `O_RDONLY`+`BLKDISCARD` on the
protected node while storming `BLKRRPART` on the whole LUN from a second
loop, then asserts the `denied` counter climbed and no KASAN report
appeared. A safety gate aborts before the destructive phase unless the
write-open is actually denied.

| Exit | Meaning |
|---|---|
| 0 | denied attempts under race, no KASAN reports |
| 1 | guard not enforcing, counter went quiet, or KASAN fired |
| 2 | wrong environment (not root, guard absent, tool missing) |
