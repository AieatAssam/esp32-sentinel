# Hardware

## Tested board

The firmware was developed and tested on one board: an **unidentified generic dev board**.
The board has no name, vendor, or model in this repository.

- SoC: ESP32-S3, QFN56 package, silicon revision v0.2.
- Flash: 16 MB, quad SPI.
- PSRAM: 8 MB, octal.
- Crystal: 40 MHz.
- USB: native USB on GPIO 19 and GPIO 20.

Other ESP32-S3 boards are untested. A board with less flash, or without octal PSRAM,
needs changes to `partitions.csv` and `sdkconfig.defaults`
(`CONFIG_ESPTOOLPY_FLASHSIZE_16MB`, `CONFIG_SPIRAM_MODE_OCT`).

## Requirements

- An ESP32-S3 with 16 MB flash and 8 MB octal PSRAM, as above.
- A USB connection that carries data to the host.
- A BOOT button on GPIO 0. It is used for download mode, FIDO user presence, and FIDO
  hardening.
- An addressable RGB LED for status, on GPIO 48 (default) or GPIO 38. The config
  validator accepts only these two values.

## Pins used by the firmware

| Signal | GPIO | Source |
|---|---|---|
| BOOT button | 0 | `main/button.c` (`BOOT_GPIO`). Read as low for 3 samples, 10 ms apart (30 ms debounce) |
| Status LED | 48 (default) or 38 | `main/config.c` (`led_gpio`, allowed values `38` and `48`) |
| USB | 19 and 20 | Native USB on the tested board. Driven by TinyUSB (`main/usb.c`) |

## Console

The console is UART0, set by `CONFIG_ESP_CONSOLE_UART_DEFAULT=y`. The USB-Serial/JTAG
console is off (`CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=n`), because TinyUSB owns that
peripheral. To read the boot log without the dashboard, connect a serial adapter to
UART0. `tools/bootlog.py` reads that port.

The UART0 pin numbers depend on the board. This repository does not record them.

## USB identity

The device presents vendor ID `0x303A` and product ID `0x4001` (`main/usb.c`). The vendor
ID belongs to Espressif. The product ID is in the range Espressif reserves for development.
Check Espressif's terms before using these IDs in a product.

## Other boards

Any other ESP32-S3 board is untested. Before using one, check:

- the flash size and PSRAM type (see above),
- the BOOT button is on GPIO 0,
- the LED is on GPIO 38 or GPIO 48,
- the native USB pins match the tested board.
