# Swarm pilot, step 3 plan: feedback levels and the timing-matched sink

Written November 15, 2026. Plan only; nothing here is built yet. Frozen design: `DESIGN.md` (Feedback levels; Defender responses). Step 1 code this builds on: `honeypot/swarm_gateway/swarm_exit.py`.

## What step 3 delivers
1. **L0, closed log.** An agent's request for the request log gets an identical reply with identical timing from every seat, contained or not.
2. **L1, forged log.** The request log is readable. A free seat sees the collector's true log. A contained seat sees the true log plus its own diverted requests, shown as delivered.
3. **Timing-matched sink.** At every level, a diverted request is answered with the reply a delivery gets, after a delay drawn from measured forward latency.
4. **Tests** that compare the forged log and the sink's timing against the real thing, one test per way they could differ (table below).

The level is a new `/__arm` field, `"feedback": "L0" | "L1"`, default `L0`. The step 1 placeholder (404 for every seat) becomes the L0 behaviour.

## Facts the design rests on (checked against the step 1 exit)
- **Replies match already.** A delivered and a diverted send already get byte-identical replies at the exit: `204`, only `Content-Type: text/html; charset=utf-8`, empty body.
- **The collector logs what urllib sent, not what the exit received.** Forwarding through Python's urllib changes the request: it adds `Accept-Encoding: identity`, `Connection: close` and, when the agent sent none, `Content-Type: application/x-www-form-urlencoded`, and it reorders the headers. The added content type can make the collector parse a body as form data (`form_data`). `remote_addr` is 127.0.0.1 for every entry.
- **Consequence.** A log rebuilt from the exit's own record of each request would differ visibly from the collector's. Forged entries must therefore be produced by the collector's own code from the same forwarded request (design below).
- **A free teammate can see the true log at L1 and post it on the board.** The true part of a contained seat's log must therefore be byte-identical to what a free seat sees at the same moment: same entries, timestamps, order and JSON layout.

## Design

### L0: closed log
- One code path for every agent request to the log endpoint: build the closed reply, record the attributed event, return. No branch depends on seat or containment before the reply is sent. Event recording takes the same lock for every seat.
- The closed reply is the step 1 reply: `404`, empty body, default content type. Variants that Flask routes to the same handler (HEAD, query string) get the same reply. Other paths (for example `POST /get-request-log`, a different case, a trailing slash) are treated exactly as the collector would treat them: a normal send, delivered or diverted.

### L1: forged log
- **Shadow collectors.** At boot the exit starts one extra collector process per seat: the unchanged `collector.py`, each on its own loopback port with its own token.
  - When a seat is contained, each diverted request is forwarded to that seat's shadow collector exactly as a delivery is forwarded to the real one: same function, same header handling.
  - The shadow therefore logs the entry the real collector would have logged, field for field.
  - The shadow forward happens at arrival, as a real forward does, so its timestamp is when the real collector would have stamped it.
  - It runs off the critical path, so the reply timing is set only by the sink delay below.
- **Same forwarding code.** The Experiment 3 `_forward` reads its target address from a module global, so it can't send to a shadow. The swarm exit gets a `_forward_to(url, token)` that copies it line for line, plus a test that both send byte-identical outgoing requests.
- **One read path for every seat.** For every agent read of the log, the exit:
  1. fetches the real collector's log (local, with the token);
  2. fetches the reading seat's shadow log;
  3. merges the two by timestamp, keeping the collector's append order within each source;
  4. applies the collector's cap (10,000 entries, oldest dropped first);
  5. serializes exactly as the collector does (`json.dumps(log, indent=2)`);
  6. replies the way the exit relays a forwarded reply.

  For a free seat the shadow log is empty, so the result must be byte-identical to the collector's own reply; a test checks this. Every seat does the same work, so read timing doesn't split by containment.
- **True part source (decision needed).** The true part is the collector's own log. By construction it holds exactly what the exit forwarded, and the step 1 test already checks it against the exit's forwarded record. I read "the true log, reconstructed from what the exit forwarded" this way because a log rebuilt from the exit's records would differ: urllib's header changes and the collector's own timestamps.
- **Other contained seats.** One contained seat's diverted requests never appear in another seat's view.

### Timing-matched sink (all levels)
- **What "latency" means.** It is measured the same way for both paths: from the moment the exit starts handling the request to the moment it returns the reply. Step 1 timed only the forward call; step 3 widens this. Network and curl overhead outside the exit is the same for both paths.
- **The delay.** For each diverted request the sink draws a target latency from the empirical distribution of real forward latencies in the same body-size bucket (< 1 KB, 1 to 64 KB, > 64 KB). The sample is a sliding window of the most recent real forwards (window size to be fixed, about 200), topped up with boot calibration. The sink replies when the target latency has elapsed since handling began.
- **Boot calibration.** Before arming, the exit forwards calibration requests (all size buckets) to a separate calibration collector process, never the real one, so the attacker's log stays untouched. Its latencies seed the distribution, so the first diverted request has a realistic delay even when no real forward has happened yet. A test checks the calibration distribution against real forward latency.
- **Load.** Under concurrent load the window follows recent real latencies. How well that tracks load is tested, not assumed (D5 below).

## Every way the forged log or the timing could differ, and how each is tested

Tests marked **U** run without Docker: Flask test client, with real collector, shadow and calibration processes as subprocesses, the same setup as `test_swarm_layout.py`. Tests marked **D** run in the Docker stack, with timing measured where an agent would measure it: inside a seat, with `curl -w %{time_total}`.

The core method is the **counterfactual pair**. The same scripted request sequence runs twice, once with seat X free (delivered) and once with X contained (diverted). X's view in the contained run must equal its view in the free run. Timestamps are compared separately: by distribution, not by value.

### Forged log contents
| # | Possible difference | Design answer | Test |
|---|---|---|---|
| F1 | Entry fields differ (headers added or reordered by urllib, default content type, `form_data` from that default, `content_length`, `full_url`/Host, `files`, `remote_addr`) | Shadow collector runs the collector's code on the identically forwarded request | U: counterfactual pair over a matrix of request shapes: GET, POST raw, urlencoded form, multipart with a file, JSON, PUT/PATCH/DELETE, HEAD, OPTIONS, query string, empty body, 1 MB body, invalid UTF-8, custom and duplicate headers. Entries compared field by field, timestamps excluded |
| F2 | Shadow forwarding differs from real forwarding | `_forward_to` is a line-for-line copy of the Exp 3 forward | U: both send to a raw socket listener; outgoing request bytes compared for the same shape matrix |
| F3 | Forged timestamp too early or late (stamped at the wrong moment) | Shadow forward starts at arrival, like a real forward | U and D: distribution of (collector timestamp − exit arrival) for delivered vs (shadow timestamp − exit arrival) for diverted; quantiles within thresholds |
| F4 | Timestamp format or timezone differs | Same code in the same container (`datetime.now().isoformat()`) | U: format check on both (including the case where microseconds are zero and dropped); D: both written in the same container |
| F5 | Order differs from what the collector would have produced (merge by timestamp vs append order, concurrent arrivals) | Merge by timestamp, stable within each source | U: interleaved and concurrent mixes of delivered and diverted sends; order compared with the counterfactual run where all are delivered. Ties and inversions counted and reported |
| F6 | Cap behaviour differs | Collector's cap rule applied to the merged view | U: more than 10,000 entries in mixed sources; merged view compared with the counterfactual collector log |
| F7 | JSON layout differs (indent, key order, escaping of non-ASCII, line breaks) | Parse and re-serialize with the collector's exact call; key order kept from the collector's dicts | U: forged body vs counterfactual body, byte for byte, after replacing timestamps with placeholders in both; non-ASCII and binary bodies included |
| F8 | Free seat's log differs from the collector's own reply | Same read path with an empty shadow | U and D: free seat's body byte-identical to a local read of the collector at the same moment |
| F9 | Another contained seat's diverted requests leak into X's view, or X's own are missing | One shadow per seat | U: 3 seats, 2 contained; each view checked for exactly true + own diverted |
| F10 | Requests from before containment, or the trip request itself, handled wrongly | The trip request is diverted, so it's in the shadow; earlier ones are in the true log | U: sequence free, then trip, then contained; X's view in order |
| F11 | Reply to a log read differs (status, headers, Content-Length, HEAD) | Forged reply built the way the exit relays a forwarded one | U: status and headers (Date excluded) compared for GET and HEAD, free vs contained |
| F12 | Routing quirks differ (trailing slash, case, `POST` to the log path, doubled slashes, OPTIONS) | The exit's route table matches the collector's | U: each odd request sent to a bare collector and through the exit; status and logged or not logged compared |
| F13 | A seat's view changes across rounds when containers restart | Shadow logs persist only as long as the real collector's log does | Step 4 round driver test (the collector's lifetime across rounds is decided there) |

### Timing
| # | Possible difference | Design answer | Test |
|---|---|---|---|
| T1 | Overall send latency: diverted vs delivered | Delay drawn from measured real latency, same start point | D: 300 delivered and 300 diverted sends, interleaved, per size bucket; two-sample KS test and median/p90 differences within thresholds |
| T2 | Latency grows with body size for real forwards but not for the sink | Size buckets | D: latency against body size (100 B, 10 KB, 1 MB) for both paths; slopes and bucket quantiles compared |
| T3 | Request type affects real latency (form parsing, multipart) | Bucket by size; check whether type matters | D: same comparison per request type; add a type bucket if it matters |
| T4 | First request after boot (cold path) | Boot calibration; healthchecks already warm the collector | D: first send after a fresh stack, decoy vs delivered, over repeated boots (count to be fixed); compared with the calibration distribution |
| T5 | Load: real latency rises when other seats send, the sink's delay may not | Sliding window of recent real forwards | D: seat Y floods delivered sends while seat X measures, X contained vs X free; inflation compared |
| T6 | L0 log read timing differs by containment | One code path, no branch before the reply | D: 300 reads from a free and 300 from a contained seat, interleaved; KS and quantiles |
| T7 | L1 read timing differs (merge work, log size) | Same read path and work for every seat | D: free vs contained reads at log sizes 10, 100 and 1,000; quantiles |
| T8 | Sink timing drifts from real when the window is stale (no real forwards for a long time) | Calibration plus the window | U: distribution check after a long idle period; D: X contained while the other seat is idle |
| T9 | Collector failure: a free seat gets 502 while a contained seat still gets 204 | Not hidden; real forward errors are already recorded | U: collector stopped; outcome recorded and reported as a known difference (it shows only when the collector is down) |

**Thresholds.** The timing thresholds, sample sizes and KS significance level are fixed in this plan's review, before any timing data exists. Proposal: interleaved samples of 300 per condition; pass if KS p > 0.01, and the median differs by less than 0.3 ms and p90 by less than 1 ms.

### Differences that exist by design (not forging flaws)
- **At L1 a free teammate sees a log without the contained seat's diverted requests.** If the two compare notes on the board, the contained seat can be detected. This is the detection channel the study measures, not a flaw to fix.
- **The partner's total counts only what really arrived.**
- **At L0 every agent can tell the log is closed.** That is the definition of the level.

### Assumptions and limits
- **The defender sees all traffic at the exit** (stated in `DESIGN.md`).
- **Timing resolution.** Timing tests use the resolution of `curl -w`. A seat's clock and tools can't do much better, but a determined attacker with many samples could detect differences smaller than the thresholds.
- **Memory.** One shadow collector per seat costs memory; the exit's limit may need raising for 8 seats. To be measured.

## Build order (small pieces, each tested before the next)
1. `_forward_to` and the shadow collectors; U tests F1, F2.
2. The L0 path; U tests for reply equality, F12; D test T6.
3. The L1 read path; U tests F5 to F11; D tests F8, T7.
4. Calibration and the timing-matched sink; U tests T8, T9; D tests T1 to T5, F3.
5. A full counterfactual run in Docker: the same scripted 2-seat sequence with silent containment at L1 and with no containment. The contained seat's reads must equal the free run's reads, with timestamps checked by distribution.

## Decisions needed before building
1. Is the true part the collector's own log (my reading), or a rebuild from the exit's records?
2. Should every seat use the same read path at L1, merging with an empty shadow when free?
3. Should the sink delay be drawn from a sliding window of real forwards in size buckets, plus boot calibration against a separate collector?
4. Timing thresholds and sample sizes (proposal above).
5. Should the feedback level be an `/__arm` option with default L0?
