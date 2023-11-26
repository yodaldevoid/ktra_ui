# ktra_ui

A CLI interface to [Ktra](https://github.com/gl-yziquel/ktra)'s web API.

Currently tested against Ktra 5.1.0.

## Usage

The following command retrieves a token from a running ktra instance.

(See [here](https://github.com/gl-yziquel/ktra) for a `ktra` repository that
compiles with correct openssl dependencies on recent ubuntus.)

```console
ktra_ui --server localhost {{USERNAME}} {{PASSWORD}}
```

This will output a token, that one may typically (though unsafely) note down
in `~/.cargo/credentials.toml`. This is required to download crates from a
standard build of `katra` with a `cargo build` command.

Overall, `ktra_ui` simplifies and streamlines the curl invocations in `ktra`'s
documentation.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
