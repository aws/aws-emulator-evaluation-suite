"""start-matchmaking-unknown-configuration-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-matchmaking-unknown-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMatchmaking with an unknown ConfigurationName is rejected with NotFoundException and
    creates no ticket, while the same call on a real configuration returns a QUEUED ticket that
    DescribeMatchmaking finds QUEUED, SEARCHING or COMPLETED against that configuration."""
    gl = ctx.client("gamelift")
    bogus_config = ctx.unique_name("sim2real-nonexistent-cfg-")
    bad_ticket_id = ctx.unique_name("sim2real-ticket-bad-")

    code, message = _error(
        lambda: gl.start_matchmaking(
            TicketId=bad_ticket_id,
            ConfigurationName=bogus_config,
            Players=[{"PlayerId": "player-1"}],
        )
    )
    assert code == "NotFoundException", f"unexpected code: {code!r}"
    expected_message = f"Specified configuration name does not exist. configurationName={bogus_config}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Unlike the by-name Describe* list operations for GameSessionQueue,
    # DescribeMatchmaking raises InvalidRequestException for a ticket ID that was
    # never created rather than returning an empty list.
    describe_code, describe_message = _error(lambda: gl.describe_matchmaking(TicketIds=[bad_ticket_id]))
    assert describe_code == "InvalidRequestException", (
        f"expected InvalidRequestException describing a never-created ticket, got {describe_code!r}"
    )
    expected_describe = f"Matchmaking ticket not found: {bad_ticket_id}"
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # Positive control: create a real ruleset + configuration and start matchmaking.
    ruleset_name = ctx.unique_name("sim2real-mm-start-ruleset-")
    gl.create_matchmaking_rule_set(
        Name=ruleset_name,
        RuleSetBody=json.dumps(
            {
                "name": "start_control",
                "ruleLanguageVersion": "1.0",
                "teams": [{"name": "solo", "minPlayers": 1, "maxPlayers": 2}],
            }
        ),
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: gl.delete_matchmaking_rule_set(Name=ruleset_name))

    config_name = ctx.unique_name("sim2real-mm-start-cfg-")
    gl.create_matchmaking_configuration(
        Name=config_name,
        RuleSetName=ruleset_name,
        RequestTimeoutSeconds=30,
        AcceptanceRequired=False,
        FlexMatchMode="STANDALONE",
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: gl.delete_matchmaking_configuration(Name=config_name))

    good_ticket_id = ctx.unique_name("sim2real-ticket-good-")
    ticket = gl.start_matchmaking(
        TicketId=good_ticket_id,
        ConfigurationName=config_name,
        Players=[{"PlayerId": "player-1"}],
    )["MatchmakingTicket"]
    ctx.on_cleanup(lambda: _safe_stop_matchmaking(gl, good_ticket_id))
    assert ticket["TicketId"] == good_ticket_id, (
        f"expected StartMatchmaking to echo TicketId {good_ticket_id!r}, got {ticket.get('TicketId')!r}"
    )
    # StartMatchmaking documents its returned ticket as QUEUED.
    assert ticket["Status"] == "QUEUED", (
        f"expected StartMatchmaking to return the ticket QUEUED, got {ticket.get('Status')!r}"
    )

    # Terminal read is independent of the mutating StartMatchmaking call: a
    # DescribeMatchmaking lookup must find the ticket, queued against the real
    # configuration, at the destination -- not just in StartMatchmaking's own response.
    described = gl.describe_matchmaking(TicketIds=[good_ticket_id])["TicketList"][0]
    assert described["TicketId"] == good_ticket_id, (
        f"expected independent DescribeMatchmaking read to find ticket {good_ticket_id!r}, "
        f"got {described.get('TicketId')!r}"
    )
    assert described["ConfigurationName"] == config_name, (
        f"expected ticket {good_ticket_id!r} to be queued against {config_name!r}, "
        f"got {described.get('ConfigurationName')!r}"
    )
    # A one-player STANDALONE ticket can be matched at once; it never needs acceptance or
    # placement, and must not have failed.
    assert described["Status"] in ("QUEUED", "SEARCHING", "COMPLETED"), (
        f"expected a freshly started ticket to be QUEUED, SEARCHING or COMPLETED, got {described.get('Status')!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _safe_stop_matchmaking(gl, ticket_id):
    try:
        gl.stop_matchmaking(TicketId=ticket_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
