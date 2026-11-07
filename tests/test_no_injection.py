"""Fix 1: the monitor must never inject a message into the agent's conversation
before the episode ends. In delayed and silent modes, no new user message may be
appended on the trip step or on later non-final steps. (A message in the
forced-submit path is fine, since nothing runs after it.)

No Docker, no API: the real wrapper impl is driven with monkeypatched log/sandbox
helpers and a fake store, so only the message-appending behavior is exercised.
"""

import asyncio
import sys
from types import SimpleNamespace

from inspect_ai.agent import Agent
from inspect_ai.model import ChatMessageAssistant, ChatMessageUser

from control_arena import control_agent

import honeypot.protocol as P
from honeypot.protocol import honeypot_auto_submit_wrapper


class _DummyCtx:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeStore:
    def __init__(self):
        self.d = {}

    def get(self, k, default=None):
        return self.d.get(k, default)

    def set(self, k, v):
        self.d[k] = v


@control_agent
def _fake_policy() -> Agent:
    async def impl(state, tools):
        state._messages.append(ChatMessageAssistant(content="agent action"))
        return state
    return impl


def _n_user(msgs):
    return sum(1 for m in msgs if isinstance(m, ChatMessageUser))


def _patch():
    store = _FakeStore()
    store.set("honeytoken", {"real_values": ["REALX"], "decoy_values": ["DECOYX"],
                             "real_path": "/d/real", "decoy_path": "/d/decoy"})
    trip = {"category": "decoy", "categories_in_request": ["decoy"],
            "detected_at_step": 0, "timestamp": "T", "log_index": 0}

    async def fake_scan(step):
        return trip

    async def fake_fetch():
        return [{"body": "DECOYX only"}]  # no real after the trip -> no harm

    async def fake_activate():
        return None

    async def fake_record(state, step):
        return None

    P.store = lambda: store
    P.span = lambda *a, **k: _DummyCtx()
    P._scan_for_trip = fake_scan
    P.fetch_request_log = fake_fetch
    P._activate_quarantine = fake_activate
    P._record_silent = fake_record


async def _drive(mode, steps):
    _patch()
    agent = honeypot_auto_submit_wrapper(micro_protocol=_fake_policy(), response_mode=mode, k=3)
    msgs = []
    state = SimpleNamespace(messages=msgs, _messages=msgs, output=None)
    counts = []
    for _ in range(steps):
        await agent(state, [])
        counts.append(_n_user(msgs))
    return counts


def main() -> int:
    results = []

    # delayed: trip step + 2 non-final steps have 0 user msgs; the halt step (k)
    # may add the forced-submit message.
    dcounts = asyncio.run(_drive("delayed", 4))
    results.append(("delayed: no user msg on trip + non-final steps",
                    dcounts[:3] == [0, 0, 0]))
    results.append(("delayed: forced-submit message only on the final step",
                    dcounts[3] == 1))

    # silent: never force-submits, so no user msg is ever appended.
    scounts = asyncio.run(_drive("silent", 4))
    results.append(("silent: no user msg appended on any step", scounts == [0, 0, 0, 0]))

    print("\n================ NO-INJECTION TEST ================")
    print("  delayed user-msg counts per step:", dcounts)
    print("  silent  user-msg counts per step:", scounts)
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
