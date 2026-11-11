"""create-participant-token-duration-boundary-rejected-over-max."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-participant-token-duration-boundary-rejected-over-max"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken rejects duration above the 20160-minute (14-day) maximum,
    while the boundary value itself succeeds."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"), tags={"sim2real": "true"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    # Positive control: the documented maximum (20160 minutes) is accepted.
    ok_token = ivsrt.create_participant_token(stageArn=stage["arn"], duration=20160)[
        "participantToken"
    ]
    assert ok_token["duration"] == 20160, ok_token["duration"]

    error = _client_error(
        lambda: ivsrt.create_participant_token(stageArn=stage["arn"], duration=20161)
    )
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == (
        "CreateParticipantToken.duration is required to have a maximum value of 20160.0, "
        "found 20161.0"
    ), error


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
