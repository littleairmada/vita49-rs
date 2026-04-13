# PCAP Reader
<!--
SPDX-FileCopyrightText: 2026 The vita49-rs Authors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

## Overview

VITA 49 data streams are often saved off to a file using tools like `tcpdump`
or `tshark`. The output format in these cases is [`.pcap`](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html).
This CLI utility takes in a `.pcap` file and tries to parse the underlying
data as VITA 49. For context packets, it prints all the fields. For data 
packets, it just prints the stream ID and payload size.

## Running

Note: this example requires `libpcap` to be available on the build system.

```
cargo run --bin pcap_reader -- <my_capture.pcap>
```
