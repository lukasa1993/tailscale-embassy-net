# tailscale-embassy-net

[![CI](https://github.com/lukasa1993/tailscale-embassy-net/actions/workflows/ci.yml/badge.svg)](https://github.com/lukasa1993/tailscale-embassy-net/actions/workflows/ci.yml)

`embassy-net` DNS, TCP, UDP, clock, and verified TLS adapters for
[`tailscale-embassy-core`](https://github.com/lukasa1993/tailscale-embassy-core).
The crate is `#![no_std]`, uses async Embassy APIs, and keeps network and TLS
buffers caller-owned.

> This is an unofficial experimental Tailscale interoperability prototype. It
> is not production-ready and must not be used to protect sensitive traffic.

The included `examples/embassy.rs` shows board-independent static-buffer wiring
for the control and DERP paths. Executor, device, flash, entropy, secure time,
and trust-anchor choices remain the responsibility of the board application.

## Use

```toml
[dependencies]
tailscale-embassy-net = { git = "https://github.com/lukasa1993/tailscale-embassy-net", default-features = false }
```

Pin a reviewed Git revision in consuming firmware.

## Verify

```sh
cargo test --all-targets
rustup target add thumbv7em-none-eabihf
cargo check --target thumbv7em-none-eabihf --no-default-features
```

## License

Licensed under either Apache-2.0 or MIT at your option.
