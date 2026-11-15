#include "usb_fido.h"

#include "tusb.h"
#include "fido/fido.h"

#define FIDO_HID_INST 0

bool usb_fido_send_report(const uint8_t report[64])
{
    if (!tud_hid_n_ready(FIDO_HID_INST)) return false;
    return tud_hid_n_report(FIDO_HID_INST, 0, report, 64);
}

void usb_fido_on_out(const uint8_t *data, size_t len)
{
    fido_hid_report_rx(data, len);
}
