# syslog_client

[![Rust](https://github.com/DoumanAsh/syslog_client/actions/workflows/rust.yml/badge.svg)](https://github.com/DoumanAsh/syslog_client/actions/workflows/rust.yml)
[![Crates.io](https://img.shields.io/crates/v/syslog_client.svg)](https://crates.io/crates/syslog_client)
[![Documentation](https://docs.rs/syslog_client/badge.svg)](https://docs.rs/crate/syslog_client/)

Syslog client

## Loggers

- [RFC 3164](https://datatracker.ietf.org/doc/html/rfc3164) - Logger is limited to buffer of 1024 bytes and splits records into chunks with common header

## Features

- `std` - Enables std types for purpose of implementing transport methods
- `log04` - Enables integration with `log` 0.4
- `tracing` - Enables integration with latest version of `tracing`
- `tracing-full` - Enables capture span content to be printed together with events. Implies `tracing` and `std`.
