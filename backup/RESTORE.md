# Restoring the original flash

Backup file: `backup/original-flash-0x0-0x200000.bin` (2097152 bytes, flash 0x0 to 0x200000).

SHA-256: `73f4e24592102de13e25244f294c9d368a16f7d7ec5e83d5466aada6962c11a1`

Verified by two independent full reads (passes 1 and 2 were byte-identical, `cmp` confirmed).

Device MAC at read time: redacted in this copy (record your own MAC locally if needed).

Partition table found in the image (offset 0x8000). This is the table of the original factory firmware and does NOT match `partitions.csv` in this repository, which describes the new layout (16 MB flash, coredump partition).

| name      | type | offset   | size     |
|-----------|------|----------|----------|
| nvs       | data | 0x009000 | 0x020000 |
| otadata   | data | 0x029000 | 0x002000 |
| phy_init  | data | 0x02b000 | 0x001000 |
| factory   | app  | 0x030000 | 0x1d0000 |

The factory app ends at 0x200000, so this 2 MiB image covers every partition in the table.

## Restore command

Put the board in ROM download mode (hold BOOT and replug). Replace the port placeholder with your device's port, then:

```
esptool --chip esp32s3 --port /dev/cu.usbmodemXXXX --before default-reset --after hard-reset write-flash --flash-mode keep --flash-freq keep --flash-size keep 0x0 backup/original-flash-0x0-0x200000.bin
```

Verify afterwards:

```
shasum -a 256 backup/original-flash-0x0-0x200000.bin
esptool --chip esp32s3 --port /dev/cu.usbmodemXXXX read-flash 0x0 0x200000 backup/restore-check.bin
shasum -a 256 backup/restore-check.bin
rm backup/restore-check.bin
```

The two hashes must match. Do not restore over a board whose backup hash does not match the value above.
