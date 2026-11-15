#pragma once

#include <stdbool.h>

/* Call first thing in app_main(). Counts abnormal resets in RTC memory. After three in a row:
 * release builds boot on in safe mode (USB, HTTP and FIDO up, radio sensing off) until a software
 * reboot or power cycle; a further crash loop inside safe mode, or any crash loop in a dev build
 * (CONFIG_DEV_BACKDOOR), reboots into ROM download mode. */
void recovery_check_on_boot(void);

/* True when this boot is in safe mode (sensing must not start). */
bool recovery_safe_mode(void);

/* Reboots. download_mode == true sets RTC_CNTL_FORCE_DOWNLOAD_BOOT so the ROM
 * bootloader comes up on the USB-Serial/JTAG port. Does not return. */
void recovery_reboot(bool download_mode);

const char *recovery_reset_reason_str(void);
