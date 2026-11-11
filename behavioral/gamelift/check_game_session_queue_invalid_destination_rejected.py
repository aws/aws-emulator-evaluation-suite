"""game-session-queue-invalid-destination-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "game-session-queue-invalid-destination-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGameSessionQueue rejects TimeoutInSeconds 5 with InvalidRequestException and creates no queue,
    accepts 10, and stores a Destinations entry naming a fleet that does not exist as given.
    """
    gl = ctx.client("gamelift")
    bad_name = ctx.unique_name("sim2real-gsq-badtimeout-")

    code, message = _error(
        lambda: gl.create_game_session_queue(Name=bad_name, TimeoutInSeconds=5)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = "TimeoutInSeconds must be between 10 and 600 seconds"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: by-name Describe silently omits missing queues.
    not_persisted = gl.describe_game_session_queues(Names=[bad_name])["GameSessionQueues"]
    assert not_persisted == [], f"expected no queue named {bad_name!r}, found {not_persisted!r}"

    # Positive control: the minimum valid TimeoutInSeconds succeeds.
    good_name = ctx.unique_name("sim2real-gsq-goodtimeout-")
    good = gl.create_game_session_queue(
        Name=good_name,
        TimeoutInSeconds=10,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["GameSessionQueue"]
    ctx.on_cleanup(lambda: gl.delete_game_session_queue(Name=good_name))
    assert good["Name"] == good_name, f"expected Name {good_name!r}, got {good['Name']!r}"
    assert good["TimeoutInSeconds"] == 10, (
        f"expected TimeoutInSeconds 10, got {good['TimeoutInSeconds']!r}"
    )

    # Deferred-validation finding: a dangling destination fleet ARN is accepted
    # verbatim rather than rejected at creation time.
    dangling_name = ctx.unique_name("sim2real-gsq-dangling-")
    bogus_fleet_arn = (
        f"arn:aws:gamelift:{ctx.region}::fleet/fleet-00000000-0000-0000-0000-000000000000"
    )
    dangling = gl.create_game_session_queue(
        Name=dangling_name,
        Destinations=[{"DestinationArn": bogus_fleet_arn}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["GameSessionQueue"]
    ctx.on_cleanup(lambda: gl.delete_game_session_queue(Name=dangling_name))
    assert dangling["Destinations"][0]["DestinationArn"] == bogus_fleet_arn, (
        f"create response should echo the dangling ARN verbatim, got "
        f"{dangling['Destinations']!r}"
    )

    # Terminal read: independent of the mutating CreateGameSessionQueue call.
    # The dangling reference must be durably persisted, not just echoed back.
    described = gl.describe_game_session_queues(Names=[dangling_name])["GameSessionQueues"]
    assert len(described) == 1, f"expected exactly one queue named {dangling_name!r}, got {described!r}"
    assert described[0]["Destinations"] == [{"DestinationArn": bogus_fleet_arn}], (
        f"expected the dangling destination to persist verbatim on independent Describe, got "
        f"{described[0]['Destinations']!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

