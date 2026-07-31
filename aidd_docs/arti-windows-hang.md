# Bug report — arti hangs on Windows while fetching the first consensus

Draft for <https://gitlab.torproject.org/tpo/core/arti/-/issues>.
Anonymous filing is possible via <https://anonticket.torproject.org/>.

Title: *arti 2.5.0 hangs during initial consensus download on Windows, one core
pegged*

---

## Reproducer

Two commands, on a Windows 11 machine with the MSVC build tools and Rust stable:

```
cargo install arti --features static-sqlite
arti proxy
```

```
2026-07-31T13:12:34Z  INFO arti::subcommands::proxy: Starting Arti 2.5.0 in proxy mode on localhost port 9150 ...
2026-07-31T13:12:34Z  INFO tor_memquota::mtracker: Memory quota tracking initialised max=8.00 GiB low_water=6.00 GiB
2026-07-31T13:12:34Z  INFO arti::proxy: Listening on [::1]:9150
2026-07-31T13:12:34Z  INFO arti::proxy: Listening on 127.0.0.1:9150
2026-07-31T13:12:34Z  INFO tor_dirmgr: Didn't get usable directory from cache.
2026-07-31T13:12:34Z  INFO tor_dirmgr::bootstrap: 1: Looking for a consensus. attempt=1
2026-07-31T13:12:35Z  INFO arti::reload_cfg: Successfully reloaded configuration.
```

Nothing further is ever printed. `arti.exe` sits at 6.2 % CPU — on a 16-thread
machine, exactly one core at 100 % — indefinitely. Bootstrap never completes and
never retries.

## What the client is doing when it stops

Captured from an embedded `arti-client` 0.44.0 with
`RUST_LOG=tor_proto=trace,tor_circmgr=trace`. The client gets much further than
the `INFO` log suggests:

```
12:52:24.856  Handshake complete; circuit created.        circ_id=Circ 0.0
12:52:24.856  Circuit creation success hop=0 delay=97.6575ms
12:52:24.857  sending relay cell ... msg: BeginDir(BeginDir)
12:52:24.858  sending relay cell ... msg: Data("GET /tor/status-vote/current/consensus-microdesc HTTP/1.0 ...")
12:52:24.887  handling cell ... cell=Relay(..)      ← several hundred of these
   ...        flow control works: Sendme in, Sendme out
12:52:25.296  handling cell ... cell=Relay(..)
              *** last log line; silence from here on ***
```

So: the directory circuit builds, the request goes out, consensus data streams
back at full speed for roughly 0.8 s, and then the client stops. arti's own
periodic tasks stop too — on a multi-threaded runtime,
`tor_circmgr::hspool: launching 3 NAIVE and 1 GUARDED circuits` keeps firing
every 30 s for twelve minutes while nothing else progresses; on a
`current_thread` runtime the whole client wedges.

One core saturated plus zero log output suggests a future being polled in a
tight loop without ever completing, rather than a lock deadlock (CPU would be
0 %) or a fault in the cell-handling path (which logs).

The stall is per-stream and it repeats. In one run the directory request was
abandoned after about ten seconds —

```
13:29:11.633  reactor shutdown  tunnel_id=Tunnel 1 reason=command channel drop
13:29:12.648  Returning existing tunnel.
13:29:12.649  sending relay cell ... msg: BeginDir(BeginDir)
13:29:12.649  sending relay cell ... msg: Data("GET /tor/status-vote/current/consensus-microdesc ...")
13:29:13.591  handling cell ... cell=Relay(..)
              *** silence again ***
```

— retried on a second circuit, streamed cells for another ~0.9 s, and stopped
the same way. So some of arti's timers do fire; what never finishes is the
directory fetch itself. The time from `GET` to silence is not constant: 0.2 s
on the first attempt, 0.9 s on the second.

Issue #2651 (congestion-control event counters not updated when the clock is
reported as stalled) looked like a fit: Windows has a ~15.6 ms clock
granularity, and a stream that stops mid-transfer with flow control still
alive is the shape it would take. It does not hold — rebuilding with
`flowctl-cc` removed from the `arti-client` feature list produces exactly the
same freeze at the same point.

## Environment

- arti 2.5.0 CLI, default features plus `static-sqlite`
- Also reproduced with embedded `arti-client` 0.44.0
- Windows 11, `x86_64-pc-windows-msvc`, Rust stable 1.97
- Reproduced on **two independent Windows machines on two different networks**

## Ruled out, with evidence

| Hypothesis | How it was ruled out |
| --- | --- |
| Network filtering Tor | A macOS client bootstraps in 3.3 s from a cold cache on the *same* Wi-Fi as one of the failing machines. On the other machine's network, Tor Browser builds a full three-hop circuit and reaches an onion service. |
| Clock skew | Log timestamps on both Windows machines agree with a reference host. |
| TLS backend | Identical behaviour with `native-tls` (schannel) and with `rustls` + `ring`. |
| Decompression (`zstd`, `xz`) | Identical with `compression` off, i.e. `accept-encoding: deflate, identity`. |
| Application code | Reproduced by the stock `arti` CLI with no third-party code. |
| Lock deadlock | CPU is not 0 %: exactly one core is saturated. |
| Congestion control (#2651) | Identical freeze with `flowctl-cc` disabled. |

## Second, unrelated finding: `cargo install arti` does not link on Windows

On a Windows machine with the MSVC build tools and nothing else, the default
feature set fails at the link step:

```
LINK : fatal error LNK1181: cannot open input file 'sqlite3.lib'
```

`rusqlite` looks for a system SQLite and Windows has none. `--features
static-sqlite` works around it. Since the README directs users to build from
source ("We expect to be providing official binaries soon"), this is the first
wall a Windows newcomer hits. Enabling `static-sqlite` by default on
`cfg(windows)` would remove it.

## Note on platform support

Windows appears to be treated as supported: `crates/arti/README.md` documents a
Windows configuration path alongside Unix and macOS, and the troubleshooting
guide names `schannel` as the Windows TLS backend. We could not find a support
tier or a published CI platform matrix, so if Windows is in fact best-effort,
saying so in the README would save people time.

## Not yet investigated

- Which thread is spinning. No native debugger was attached.
