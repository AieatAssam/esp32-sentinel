# Sensing

The device infers presence from the radio environment. It uses no camera and no
microphone. The estimates are heuristics. They have not been measured against ground
truth in this repository, and they are not a safety system.

## Inputs

- **Wi-Fi CSI.** Channel state information from the Wi-Fi driver, enabled by
  `CONFIG_ESP_WIFI_CSI_ENABLED=y` in `sdkconfig.defaults`. People moving in a room change
  the CSI amplitude.
- **Beacon RSSI.** Promiscuous-mode beacon frames from nearby access points. Used for
  signal level, distance, and the threat checks.
- **BLE observer.** NimBLE in observer role only (`CONFIG_BT_NIMBLE_ROLE_OBSERVER=y`).
  The broadcaster, central, and peripheral roles are off. The device does not advertise
  or connect. It classifies tracker advertisements (AirTag, Find My, Tile, SmartTag) for
  the threat view.

## Estimates

Implemented in `main/sensing.c` and `main/sensing_dsp.c`. Values are in the tables below.

- **Motion.** Score from the per-subcarrier CSI variation, smoothed with an EWMA of 0.3
  per 100 ms tick. Compared against `motion_threshold` (default 0.15).
- **Breathing.** Experimental. A band-limited estimate from the CSI series. Shown and counted
  as presence only when its gates pass (below). Enabled by default (`use_breathing`). It has
  not been seen to read in testing; see [what was measured](#breathing-what-was-measured).
- **Baseline.** An empty-room baseline stored in NVS (namespace `app`, key `base`).
  Captured with `POST /api/calibrate` while the room is empty. Off by default
  (`use_baseline`).
- **Presence.** Motion, breathing, and baseline are evaluated in that order in
  `tick_locked()`. The first one that holds sets `why` in the feed.
- **Away.** Presence absent for `away_secs` (default 30 s, range 5 to 600). When
  auto-lock is on, the lock is sent once per away period. It is retried every 2 s while
  still away, if the send failed.

## Breathing gates

A breathing estimate is produced only when the window passes these checks, in
`breath_pass()`:

- The window is 30 s long (`BR_WIN_US`), filled from CSI samples at 10 Hz (300 samples,
  `BR_N`, each a 100 ms bin).
- The first sample must fall within 2 s of the window start (`BR_GAP_US`), and no gap in
  the window may be longer than 2 s.
- The mean CSI sample rate over the window must be at least 1.5 per second
  (`BR_MIN_FPS`).
- Breathing is withheld while motion is above 0.5 (`BR_MOTION_MAX`).
- The estimate is shown in the feed only above confidence 0.2 (`BR_CONF_SHOW`), and
  counts as presence only above confidence 0.5 (`BR_CONF_PRESENT`).

The gate state is logged. Breathing estimates are not medical measurements.

## Breathing: what was measured

One 6-minute raw capture on a joined AP (20 Hz gateway ping, about 20 downlink CSI frames/s
addressed to the device, no gaps), with a person about 1 m from the board working at a laptop.
Analysed offline in 11 non-overlapping 30 s windows, each feature against an AR(1) noise model
fitted to the same window:

- Features tried: mean amplitude (what the firmware uses), RSSI, per-frame normalised
  amplitudes (removes AGC) reduced by PCA, the best single subcarrier chosen on the previous
  window, and adjacent-subcarrier phase difference reduced by PCA. Each with all downlink
  frames of the AP and with only the frames addressed to the device.
- 2 of 110 window tests beat the noise model, and no feature beat it in more than one window.
  Peak rates jumped across the 6 to 30 per minute band from window to window, and the 10 Hz
  series were close to white (lag-1 autocorrelation about 0.05).
- Sensitivity: a steady 15 per minute sinusoid added to the recorded mean amplitude would have
  been found in 8 of 11 windows at 1% of the mean amplitude and in all 11 at 2%. Irregular
  breathing, or breathing under the movement of typing, could be larger and still be missed.

So the gates and thresholds are left as they are: they correctly kept the estimate hidden. A
reading needs a geometry where the chest moves a path that dominates the channel (closer to the
device or between it and the AP) and a still person; that has not been tested. Raw captures for
this kind of analysis come from `tools/csi_capture.py` on a development build.

## Trust: which access points count for presence

A passive receiver cannot authenticate 802.11 frames, so not every access point may feed
presence. An AP counts when it is trusted:

- **Empty-room baseline.** APs seen when the baseline was captured are trusted.
- **Joined AP.** The access point the device joins in joined mode is trusted.
- **Learned.** An AP that beacons steadily for `THR_LEARN_S` (600 s) since admission is
  learned. A gap longer than `THR_LEARN_GAP_S` (5 s) restarts the learning clock.

A BSSID that has just appeared does not count.

**Bootstrap.** After boot, or after a channel change, untrusted APs count only while no
AP is trusted yet (`THR_BOOTSTRAP_S`, 600 s). This lets presence work immediately.

**Spoofed never counts.** A BSSID flagged as spoofed (below) never counts, whatever its
trust state.

Unknown BSSIDs can hold at most 10 alert slots (`THR_UNKNOWN_MAX`), so a flood of
spoofed BSSIDs cannot crowd out alerts for trusted APs.

## Spoof detection

Beacon anomalies suggest a second transmitter using the same BSSID. An anomaly is a
repeated or backwards 802.11 sequence number, a TSF timestamp that runs backwards, or a
TSF advance that differs from the local clock advance by more than 50 ms
(`THR_BCN_TSF_TOL_US`). Anomalies are counted in a 10 s window (`THR_BCN_WIN_S`). When
the count reaches 3 (`THR_BCN_ANOMALIES`), the BSSID is flagged for 60 s
(`THR_BCN_HOLD_S`). Each further anomaly while the count is at or above 3 extends the
flag by another 60 s. The flag appears as `flag: "spoof"` on the AP in the feed.

## Tunables

Values are from `main/sensing.c` (lines 41 to 78) and `main/threats.h`. The config
values are from `main/config.c`.

### Access points and BLE

| Name | Value | Effect |
|---|---|---|
| `AP_TABLE` | 16 | BSSIDs tracked |
| `AP_OUT` | 12 | APs sent in each feed frame, strongest first |
| `AP_AGE_US` | 60 s | An AP not seen for this long is dropped |
| `BLE_TABLE` | 24 | BLE devices tracked |
| `BLE_TTL_US` | 30 s | A BLE device not seen for this long is dropped |
| `BLE_SCAN_ITVL` | 100 ms | BLE scan interval (160 units of 0.625 ms) |
| `BLE_SCAN_WIN` | 30 ms | BLE scan window (48 units), about 30% duty, to limit Wi-Fi coexistence cost |
| `RSSI_RING` | 64 | Beacon RSSI samples kept per AP |
| `RSSI_WIN_US` | 3 s | Window for the RSSI spread |
| `RSSI_SD_FLOOR` | 0.7 dB | Spread below this is treated as quantisation (RSSI is whole dBm) |
| `RSSI_SD_FULL` | 3.0 dB | Spread that maps to motion 1.0 |

### Motion, CSI, and baseline

| Name | Value | Effect |
|---|---|---|
| `CSI_TAU_S` | 3.0 s | EWMA time constant of per-subcarrier mean and variance |
| `CSI_WARM` | 20 samples | Samples needed before an AP's CSI statistics are used |
| `CSI_MIN_FPS` | 2.0 /s | Below this, an AP's CSI is not used for motion or baseline |
| `CSI_MOTION_FULL` | 0.08 | Mean per-subcarrier standard deviation of normalised amplitude that maps to motion 1.0 |
| `MOTION_EWMA` | 0.3 | Motion smoothing per 100 ms tick |
| `BASE_SHAPE_FULL` | 0.10 | Mean absolute shape difference that maps to baseline deviation 1.0 |
| `BASE_DB_FULL` | 4.0 dB | RSSI shift from the baseline that maps to deviation 1.0, used when there is no CSI |
| `BASE_DEV_PRESENT` | 0.5 | Baseline deviation that counts as presence |
| `BASE_CAPTURE_S` | 10 s | Length of a baseline capture |
| `BASE_MIN_SAMPLES` | 5 | Samples needed for a baseline to be stored |

### Breathing

| Name | Value | Effect |
|---|---|---|
| `BR_N` | 300 | Samples in the series (30 s at 10 Hz) |
| `BR_BIN_US` | 100 ms | CSI averaged into one series sample |
| `BR_WIN_US` | 30 s | Window length |
| `BR_GAP_US` | 1 s | Longest gap allowed in the window (also the start tolerance) |
| `BR_MIN_FPS` | 1.5 /s | Minimum mean CSI rate to attempt breathing |
| `BR_MOTION_MAX` | 0.5 | Breathing withheld above this motion |
| `BR_CONF_SHOW` | 0.2 | Confidence needed to show the breath value |
| `BR_CONF_PRESENT` | 0.5 | Confidence needed for breathing to count as presence |

### Channel scan and joined mode

| Name | Value | Effect |
|---|---|---|
| `BEACON_MIN_FPS` | 1.0 /s | Beacon rate below this counts as a collapse |
| `BEACON_LOW_S` | 30 s | A collapse must last this long before a rescan |
| `REPICK_US` | 180 s | At most one rescan per this period (channel 0 only, not joined, not calibrating) |
| `JOIN_TRIES` | 3 | Attempts to join the configured network |
| `PING_PERIOD_MS` | 50 ms | ICMP echo interval to the joined gateway (20 Hz) |
| `TICK_MS` | 100 ms | Sensing tick |

### Distance

| Name | Value | Effect |
|---|---|---|
| `DIST_RSSI_1M` | -40 dBm | RSSI at one metre, for the log-distance estimate |
| `DIST_N` | 2.5 | Path-loss exponent |

Distance from signal strength is an estimate. The direction of a source is not
measured with one antenna.

### Threats

| Name | Value | Effect |
|---|---|---|
| `THR_DEAUTH_BURST` | 20 frames | Deauth and disassociation frames per BSSID that flag it |
| `THR_DEAUTH_WIN_S` | 10 s | Sliding window for deauth frames |
| `THR_DEAUTH_QUIET_S` | 30 s | A deauth flag clears after this long with no such frame |
| `THR_TRACKER_ALERT_S` | 600 s | A tracker-kind device followed this long raises an alert |
| `THR_TRACKER_GAP_S` | 60 s | A gap longer than this restarts the following clock |
| `THR_SLOTS` | 16 | Deauth and evil-twin alert slots |
| `THR_ALERT_OUT` | 8 | Alerts sent in each frame |
| `THR_UNKNOWN_MAX` | 10 | Alert slots that BSSIDs outside the trusted set may hold |
| `THR_LEARN_S` | 600 s | Steady beaconing needed before an AP is learned |
| `THR_LEARN_GAP_S` | 5 s | A beacon gap longer than this restarts learning |
| `THR_BOOTSTRAP_S` | 600 s | Period after boot or a channel change when untrusted APs count |
| `THR_BCN_TSF_TOL_US` | 50 ms | TSF advance tolerance against local time |
| `THR_BCN_WIN_S` | 10 s | Window for counting beacon anomalies |
| `THR_BCN_ANOMALIES` | 3 | Anomalies in one window that flag a BSSID as spoofed |
| `THR_BCN_HOLD_S` | 60 s | How long a spoofed flag lasts after the last anomaly |
| `THR_AP_STALE_S` | 5 s | An untrusted AP not heard for this long may be replaced |
| `THR_AP_MIN_BEACONS` | 5 | An untrusted AP with fewer beacons than this may be replaced |
| `THR_TRK_SLOTS` | 16 | Tracker slots |

### User settings (`main/config.c`)

| Setting | Default | Range |
|---|---|---|
| `away_secs` | 30 s | 5 to 600 |
| `motion_threshold` | 0.15 | 0 to 1 |

## Feed fields

The WebSocket feed fields, and the `flag` values, are listed in
[ARCHITECTURE.md](ARCHITECTURE.md#websocket-feed). `tools/ws_check.py` checks them.

## Fault state

If sensing cannot start (for example, out of memory, or a task fails to create), or the
device is in safe mode after repeated crashes, the feed sends a fault frame with
`stub: true` and a `fault` string. The presence fields are then fixed (present, no
access points), so the dashboard can show the fault rather than a stale estimate.

## Limitations

- Accuracy has not been measured in this repository. No test data, no ground truth, and
  no error figures are published with 0.1.0.
- Pets, fans, and other people in the room change the estimates.
- Walls, furniture, and the device's position change the baseline. Recalibrate after
  moving the device.
- Presence estimates can be wrong in both directions. Do not use them to protect
  anything that matters.
