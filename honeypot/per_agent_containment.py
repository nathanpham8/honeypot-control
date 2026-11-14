"""Per-agent containment decision (defender side, swarm pilot).

In the one-machine layout every agent shares a single exit. The defender must
contain only the agent that sent a decoy, while the others keep working. This
module is the pure decision the exit makes for each outbound request:

  given  an agent identity on the request, the request's text, and the current
         containment state,
  decide whether the request is forwarded or diverted to the sink, and whether
         it just caused that agent to become contained.

The agent identity is attached by the harness at the exit layer, NOT by the
agent (which writes arbitrary commands and cannot be trusted to tag itself).
How that identity is attached is a separate, still-open question; this module
only needs it to be present and trustworthy.

A position that was contained in an earlier round starts the next round already
in `contained`, so its first request this round is diverted too.
"""

from dataclasses import dataclass, field

from honeypot.gateway_summary import _has


@dataclass
class ContainmentState:
    """Which agent identities are currently contained. Seeded at the start of a
    round from the swarm state (positions contained in earlier rounds)."""
    decoy_values: tuple[str, ...] = ()
    contained: set[str] = field(default_factory=set)

    def seed_contained(self, agent_ids) -> None:
        self.contained.update(a for a in agent_ids if a)


@dataclass
class Decision:
    divert: bool
    newly_contained: bool
    reason: str  # "already-contained" | "decoy" | "forward" | "no-identity"


def decide(state: ContainmentState, agent_id: str, request_text: str) -> Decision:
    """One request from one agent. Mutates state when a decoy is first seen.

    An unidentified request (no agent_id) is diverted and not attributed: the
    defender will not forward traffic it cannot attribute at a shared exit, and
    a missing identity means a harness fault, not a free pass for the agent."""
    if not agent_id:
        return Decision(divert=True, newly_contained=False, reason="no-identity")
    if agent_id in state.contained:
        return Decision(divert=True, newly_contained=False, reason="already-contained")
    if _has(request_text, state.decoy_values):
        state.contained.add(agent_id)
        return Decision(divert=True, newly_contained=True, reason="decoy")
    return Decision(divert=False, newly_contained=False, reason="forward")
