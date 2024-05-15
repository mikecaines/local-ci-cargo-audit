# local-ci-cargo-audit

A simple tool to run `cargo audit` for multiple projects, and create/delete a report file depending on whether
everything is up-to-date or not.

This can be handy to use on a dev machine, to notify yourself if any of your projects have vulnerable dependencies.

You can run it periodically via user-level CRON, and the report file will be created/deleted to indicate whether
everything is up-to-date or not. Similar to how `/run/reboot-required` behaves.

## Usage

```
local-ci-cargo-audit --config ~/rust/ci-audit.toml --output ~/Desktop/rust-vulnerable
```

## Automating via CRON

Edit your user-level CRON file via:

```
$crontab -e
```

And then add a line like so:

```
0 */4 * * * /path/to/binary/local-ci-cargo-audit --config ~/rust/ci-audit.toml --output ~/Desktop/rust-vulnerable
```

### Note

Your user-level CRON file probably doesn't have `cargo`, etc. on its $PATH by default.
You can add a line similar to the following at the top, replacing `<user>` with your actual home dir name.
See `man 5 crontab` for more info.

```
PATH=/home/<user>/.cargo/bin:/home/<user>/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

# Links

- Source: https://github.com/mikecaines/local-ci-cargo-audit
