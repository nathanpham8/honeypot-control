# Swarm pilot, step 1: plan (under review)

## The plan in five lines
1. The swarm pilot asks whether silent containment still works when 2 agents (later 4 and 8) share a board and can check each other's results.
2. Each agent gets its own container and network address, the same 8 real/decoy credential pairs, and a shared board volume. Rounds run in parallel, and agents restart with no memory except the board.
3. The harness writes the board header: a roster and the partner's pooled total, updated only between rounds. Agents add signed, append-only notes below it.
4. Each run uses one defender response: silent containment, visible shutdown, or none. The exit identifies the agent by its container's address, and containment stays with the position across restarts.
5. Remaining work: de-risk the multi-container exit, wire it into the gateway and `SwarmState`, build the parallel round driver, write records and analysis, then freeze prompts and log the mini-pilot before any data exists.

## Proposed container layout (step 1)

**Networks: one private network per agent, plus the outer one.** Agent containers do not share a network. Seat *i* sits alone on its own network `seat_i`, and only the router is attached to all of them. I'll use Docker's `interface_name` so the router's interfaces are always named `seat0`, `seat1` and `outer`. (The stock router script guesses its interfaces and can only handle one inner network.)

Why separate networks: agents keep `NET_ADMIN`/`NET_RAW` from the stock compose. On a shared network, agent A could take B's IP address and MAC address, and the router could not tell them apart. With one network per seat, the interface a packet arrives on is the identity, and agents cannot forge it.

**Router: a new swarm router script.** It does what the stock script does, but for each seat interface:
- the same DNAT rules for the three fake external addresses;
- an anti-spoof rule that drops anything arriving on `seatN` whose source is outside `seatN`'s subnet. It goes in the raw table so it runs before DNAT, has its own counter, and also blocks spoofed `127.0.0.1` reaching the exit's control endpoints;
- strict `rp_filter`;
- no forwarding from one agent network to another.

**Exit: the existing Exp 3 path with a thin per-seat layer.** The Exp 3 gateway has one global "contained" flag, so as it stands it would contain both agents. I won't edit it. A new `swarm_exit.py` imports the existing gateway's request capture, flatten and forward helpers and the collector startup, so forwarding stays identical. It replaces only the decision step:
- it maps `remote_addr` to a seat by subnet;
- it calls the existing `per_agent_containment.decide()`;
- it logs one attributed event for every request (seat, address, decision).

The collector is unchanged. It is built as its own image, `bash-arena-swarm-exit:latest`. The harness reads each seat's subnet from the router and sends the map to the exit through the existing localhost-only `/__arm` call.

**Board:** a named volume `board` mounted at `/opt/coalition` in both agent containers.

**The test (`tests/test_swarm_exit_e2e.py`):** it drives plain `docker compose` from Python, using the practice task image `38927895` that is already built. It doesn't use Inspect or a model; Inspect wiring is step 2. In order:
1. Both containers write and read the shared board.
2. A takes B's address, sends a decoy as B, and the attempt fails: the router's drop counter goes up and nothing reaches the exit or the collector.
3. A sends a harmless value and it reaches the collector.
4. B starts a detached background process that sends a decoy. The request is attributed to B, B is contained, and A is not.
5. B's next request goes to the sink.
6. A's next request still reaches the collector.

## What it touches
- **New files:**
  - `honeypot/swarm_layout.py` (compose generator for N seats);
  - `honeypot/swarm_router.sh`;
  - `honeypot/swarm_gateway/{swarm_exit.py, service.Dockerfile}`. The build context is `honeypot/`, so it can copy the existing gateway, collector and containment modules unchanged;
  - a no-Docker test `tests/test_swarm_layout.py` covering the compose text, the router rules and the exit's seat/decision logic run through the Flask test client;
  - the e2e test.
- **Changed:** only `DESIGN.md` (the build status row and the attribution paragraph). Nothing in `gateway_server/`, `plant.py`, the compose templates, protocol or setting changes, so Exp 3 and earlier arms stay as they are.
- `experiment_log.md`: no entry. This is a scripted infrastructure test, not an experiment or arm, but tell me if you'd rather log it.

## Decide before I start
1. **Agent-to-agent networking.** I plan to block it, so the board is the only channel between agents and every message lands in the authorship record. Say if you want agents able to reach each other.
2. **Scope.** Step 1 needs a minimal per-seat exit to show the property. I'm treating that as part of step 1 and leaving step 2 as the Inspect/`SwarmState` wiring. Say if you'd rather draw the line differently.
3. **Subnet pool.** This machine's default Docker pool is nearly used up: my probe got `172.30`, `172.31` and then `192.168.x/20`. An 8-agent swarm needs 9 networks, so parallel swarms will need a smaller daemon `default-address-pools` setting or explicit subnets. I'll note it in `DESIGN.md` but not fix it now.
