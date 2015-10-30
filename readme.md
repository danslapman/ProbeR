# ProbeR
ProbeR is a simple MPEG-TS stream analyser utility written in Rust.

ProbeR can do the following things:
* Detect CC errors
* Detect scrambling
* Calculate stream bitrate

ProbeR binds socket with SO_REUSEADDR, so you can run multiple instances of ProbeR on one machine.