"""create-participant-token-duration-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-participant-token-duration-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken accepts durations 1 and 20160 and rejects a duration above 20160 with
    ValidationException and the exact message; botocore refuses values below 1 locally."""
    ivs = ctx.client("ivs-realtime")
    stage_arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    # Positive control: the minimum boundary (1 minute) is honored, not silently
    # bumped up to some other floor.
    low_token = ivs.create_participant_token(stageArn=stage_arn, duration=1)["participantToken"]
    assert low_token["duration"] == 1, low_token["duration"]

    # Positive control: the maximum boundary (20160 minutes) is accepted.
    high_token = ivs.create_participant_token(stageArn=stage_arn, duration=20160)["participantToken"]
    assert high_token["duration"] == 20160, high_token["duration"]

    # Above the maximum is rejected by the service (this is the only direction
    # of the range boto3 lets an out-of-range value reach AWS for).
    high = _client_error(lambda: ivs.create_participant_token(stageArn=stage_arn, duration=20161))
    assert high.get("Code") == "ValidationException", high
    assert high.get("Message") == (
        "CreateParticipantToken.duration is required to have a maximum value of 20160.0, "
        "found 20161.0"
    ), high


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
