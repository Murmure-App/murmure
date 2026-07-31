# Bug report — arti 0.44.0 hangs on Windows during consensus download

Draft for <https://gitlab.torproject.org/tpo/core/arti/-/issues>.
Title suggestion: *Client hangs with one core pegged while downloading the
first consensus (Windows, 0.44.0)*.

---

## Summary

On Windows, `arti-client` 0.44.0 reaches 15 % of bootstrap, builds a one-hop
directory circuit, sends the consensus request, receives several hundred relay
cells over roughly 0.8 s — and then stops making progress permanently. One CPU
core stays at 100 % indefinitely. No further log output at `TRACE`, and arti's
own periodic tasks (e.g. `tor_circmgr::hspool`) never fire again.

Reproduced on **two independent Windows machines on two different networks**.
The same code bootstraps in **3.3 s** on macOS from a cold cache.

## Versions

- `arti-client` 0.44.0, embedded (not the `arti` CLI)
- Windows 11, x86_64-pc-windows-msvc
- Rust stable 1.97
- Features: `tokio`, `compression`, `flowctl-cc`, `rustls`, `experimental-api`,
  `onion-service-client`, `onion-service-service`, `static-sqlite`

## What it looks like

```
[   0.0s] 0%
[   0.1s] 8%
[   0.2s] 15%
<nothing further; one core at 100 % forever>
```

Trace excerpt, the last thing that happens:

```
12:52:24.856  Handshake complete; circuit created.        circ_id=Circ 0.0
12:52:24.856  Circuit creation success hop=0 delay=97.6575ms
12:52:24.857  sending relay cell ... msg: BeginDir(BeginDir)
12:52:24.858  sending relay cell ... msg: Data("GET /tor/status-vote/current/consensus-microdesc HTTP/1.0 ...")
12:52:24.887  handling cell ... cell=Relay(..)     ← hundreds of these
   ...        (flow control works: Sendme in, Sendme out)
12:52:25.296  handling cell ... cell=Relay(..)
              *** last log line, 60+ s of silence ***
```

## What we ruled out, with evidence

| Hypothesis | How it was ruled out |
| --- | --- |
| Network filtering Tor | A macOS client bootstraps in 3.3 s on the *same* Wi-Fi. On the other machine's network, Tor Browser builds a full circuit and reaches an onion service. |
| Clock skew | Log timestamps on both Windows machines agree with a reference host to within a minute. |
| TLS backend | Identical behaviour with `native-tls` (schannel) and with `rustls` + `ring`. |
| Decompression (`zstd` / `xz`) | Identical behaviour with `compression` disabled, i.e. `accept-encoding: deflate, identity`. |
| Application code | Reproduced by a bare `bootstrap_client` call with no UI and no other tasks. |
| Deadlock on a lock | CPU is not 0 %: exactly one core is saturated. It is a spin, not a block. |

## Interpretation

One future appears to be polled in a tight loop without ever completing. The
CPU figure (6.25 % of a 16-thread machine = exactly one core) and the total
absence of log output point at a poll loop rather than at the cell-handling
path, which does log.

On a `current_thread` runtime the whole client wedges, which matches the
observation above. On a multi-threaded runtime, unrelated periodic tasks keep
running while bootstrap never finishes — which is what the first machine showed
at `DEBUG` level: `hspool: launching 3 NAIVE and 1 GUARDED circuits` kept
appearing every 30 s for twelve minutes while nothing else progressed.

## Not yet checked

- Whether the `arti` CLI (`arti proxy`) shows the same hang. That would separate
  "arti on Windows" from "this feature combination".
- Which thread is spinning. No native debugger was attached.
