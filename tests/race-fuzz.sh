#!/bin/sh
# race-fuzz.sh — Partition Guard resolution race test.
#
# Hammers the exact race the ref-pinned dev_t resolution closes:
#   T1: BLKRRPART on the whole LUN (partition-table rescan -> delete_partition)
#   T2: write-open / BLKDISCARD on the protected node (guard lookup path)
# Lookup runs before the verdict, so even DENIED attempts exercise it.
#
# Run on a KASAN-instrumented test kernel, as root:
#   DISK=/dev/block/sdc PART=/dev/block/sdc35 LABEL=nvram DUR=60 sh race-fuzz.sh
#
# Exit: 0 PASS, 1 FAIL (enforcement or KASAN), 2 environment.
# Never run on a production kernel you care about: BLKRRPART on the live
# LUN should fail EBUSY, but this is the test that proves it, not assumes it.
set -u

LABEL="${LABEL:-nvram}"
PART="${PART:-/dev/block/by-name/$LABEL}"
DUR="${DUR:-60}"
SYS=/sys/kernel/partition_guard

pass() { echo "PASS: $*"; exit 0; }
fail() { echo "FAIL: $*" >&2; exit 1; }
skip() { echo "SKIP: $*" >&2; exit 2; }
note() { echo ".... $*"; }

[ "$(id -u)" = "0" ] || skip "must run as root"
for t in timeout blockdev dd cat grep sed readlink; do
	command -v "$t" >/dev/null 2>&1 || skip "missing tool: $t"
done

# Resolve the partition node through by-name (board-agnostic), then
# derive the whole-disk node by stripping the partition suffix:
# sdc35 -> sdc, mmcblk0p24 -> mmcblk0, nvme0n1p2 -> nvme0n1.
# DISK may still be overridden directly when the layout is unusual.
[ -e "$PART" ] || skip "$PART missing — set PART=/dev/block/... explicitly"
REAL=$(readlink -f "$PART" 2>/dev/null || readlink "$PART")
case "$REAL" in
/*) ;;
*) REAL="/dev/block/$REAL" ;;
esac
DISK="${DISK:-$(printf '%s' "$REAL" | sed 's/[0-9][0-9]*$//; s/p$//')}"
[ -b "$DISK" ] || skip "derived DISK=$DISK is not a block node — set DISK= explicitly"
[ "$DISK" != "$REAL" ] || skip "could not separate disk from partition ($REAL) — set DISK= explicitly"
note "target: $REAL on $DISK (label $LABEL)"

# 1. Guard alive?
[ -d "$SYS" ] || fail "no $SYS — guard init never ran"
[ "$(cat "$SYS/enabled")" = "1" ] || fail "guard disabled"
grep -qx "$LABEL" "$SYS/protected" 2>/dev/null \
	|| note "$LABEL not listed in protected (continuing anyway)"

# 2. SAFETY GATE: enforcement must work BEFORE any destructive ioctl.
# count=0 transfers nothing; the write-open itself must die with EPERM.
# If the open succeeds, the guard is not enforcing and BLKDISCARD below
# would really erase the first 4K of the partition — so refuse to continue.
if dd if=/dev/zero of="$PART" bs=512 count=0 2>/dev/null; then
	fail "write-open of $PART ALLOWED — guard not enforcing, destructive phase refused"
fi
note "safety gate: write-open denied as expected"

# 3. KASAN?
if dmesg | grep -qi kasan; then
	note "KASAN instrumented kernel detected"
else
	note "no KASAN in dmesg — race still exercised, UAF invisible without it"
fi

BEFORE=$(cat "$SYS/denied")
note "denied-before: $BEFORE"

# Phase 1: O_WRONLY open storm (writes nothing) vs rescan storm.
note "phase 1/${DUR}s: write-open storm on $PART + BLKRRPART on $DISK"
timeout "$DUR" sh -c "while true; do dd if=/dev/zero of=$PART bs=512 count=0 2>/dev/null; done" &
P1=$!
timeout "$DUR" sh -c "while true; do blockdev --rereadpt $DISK 2>/dev/null; done" &
P2=$!
wait $P1 $P2

# Discard issuer, best first: raw ioctl binary (tests/guard-ioctl.c) or
# python3 issue O_RDONLY + BLKDISCARD, which reaches the ioctl hook.
# busybox blkdiscard opens O_WRONLY, so it only re-tests the open hook —
# still useful race load, but named honestly.
ISSUER="${ISSUER:-/data/local/tmp/guard-ioctl}"
if [ -x "$ISSUER" ]; then
	note "discard issuer: $ISSUER (ioctl path)"
	DO_DISCARD="$ISSUER $REAL 2>/dev/null"
elif command -v python3 >/dev/null 2>&1; then
	note "discard issuer: python3 (ioctl path)"
	DO_DISCARD="python3 -c 'import fcntl,os,struct; fd=os.open(\"$REAL\",os.O_RDONLY)
try:
 fcntl.ioctl(fd,0x1277,struct.pack(\"QQ\",0,4096))
except OSError: pass
os.close(fd)' 2>/dev/null"
else
	for BB in /data/adb/ksu/bin/busybox busybox; do
		if "$BB" blkdiscard --help >/dev/null 2>&1; then
			note "discard issuer: $BB blkdiscard (open path only — no ioctl coverage)"
			DO_DISCARD="$BB blkdiscard -o 0 -l 4096 $REAL 2>/dev/null"
			break
		fi
	done
	[ -n "${DO_DISCARD-}" ] || skip "no BLKDISCARD issuer (guard-ioctl, python3, or busybox)"
fi

# Phase 2: BLKDISCARD storm (ioctl resolution) vs rescan storm.
# Denied by the hook — but lookup runs first, which is what we are testing.
note "phase 2/${DUR}s: BLKDISCARD storm on $REAL + BLKRRPART on $DISK"
timeout "$DUR" sh -c "while true; do $DO_DISCARD; done" &
P3=$!
timeout "$DUR" sh -c "while true; do blockdev --rereadpt $DISK 2>/dev/null; done" &
P4=$!
wait $P3 $P4

AFTER=$(cat "$SYS/denied")
note "denied-after: $AFTER"
[ "$AFTER" -gt "$BEFORE" ] 2>/dev/null \
	|| fail "denied counter did not climb ($BEFORE -> $AFTER) — hook went quiet mid-race"

if dmesg | grep -i "kasan" | grep -viE "kasan\.|KASAN_SHADOW|kasan_flag|kasan_init|shadow" | grep -q .; then
	dmesg | grep -i kasan | tail -20 >&2
	fail "KASAN report present — use-after-free in the lookup path"
fi

pass "denied $((AFTER - BEFORE)) attempts under rescan race, no KASAN reports"
