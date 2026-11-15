#pragma once

#include "esp_err.h"

/* Creates the USB network interface 192.168.7.1/24 with a DHCP server that hands out
 * 192.168.7.2 and advertises no router and no DNS. Call before usb_init(). */
esp_err_t net_init(void);
