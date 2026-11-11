"""stop-matchmaking-transitions-to-cancelled."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stop-matchmaking-transitions-to-cancelled"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A matchmaking ticket that is actively searching (no fleet destinations, so it
    can never actually match) transitions to CANCELLED after StopMatchmaking, and
    a follow-up DescribeMatchmaking poll confirms the terminal state persists."""
    gl = ctx.client("gamelift")
    ruleset_name = ctx.unique_name("sim2real-mm-stop-ruleset-")
    gl.create_matchmaking_rule_set(
        Name=ruleset_name,
        RuleSetBody=json.dumps(
            {
                "name": "stop_test",
                "ruleLanguageVersion": "1.0",
                "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
            }
        ),
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: gl.delete_matchmaking_rule_set(Name=ruleset_name))

    config_name = ctx.unique_name("sim2real-mm-stop-cfg-")
    gl.create_matchmaking_configuration(
        Name=config_name,
        RuleSetName=ruleset_name,
        RequestTimeoutSeconds=600,
        AcceptanceRequired=False,
        FlexMatchMode="STANDALONE",
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: gl.delete_matchmaking_configuration(Name=config_name))

    ticket_id = ctx.unique_name("sim2real-mm-stop-ticket-")
    started = gl.start_matchmaking(
        TicketId=ticket_id,
        ConfigurationName=config_name,
        Players=[{"PlayerId": "player-1"}],
    )["MatchmakingTicket"]
    assert started["Status"] in ("QUEUED", "SEARCHING"), (
        f"expected the fresh ticket QUEUED or SEARCHING, got {started['Status']!r}"
    )

    gl.stop_matchmaking(TicketId=ticket_id)

    final = _poll_until(
        lambda: gl.describe_matchmaking(TicketIds=[ticket_id])["TicketList"][0],
        lambda t: t["Status"] == "CANCELLED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert final["Status"] == "CANCELLED", f"expected CANCELLED, got {final['Status']!r}"
    assert "EndTime" in final, "a terminal ticket must carry an EndTime"

    # The terminal state must persist, not just have been observed once in transit: three
    # consecutive independent reads, spaced out, must all still say CANCELLED.
    _assert_persists(
        lambda: gl.describe_matchmaking(TicketIds=[ticket_id])["TicketList"][0]["Status"],
        expected="CANCELLED",
        reads=3,
        interval_s=2.0,
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _assert_persists(probe, *, expected, reads=3, interval_s=2.0):
    for i in range(reads):
        if i:
            time.sleep(interval_s)
        actual = probe()
        if actual != expected:
            raise AssertionError(
                f"expected {expected!r} to persist, got {actual!r} on read {i + 1}/{reads}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
