"""create-participant-token-attributes-size-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-participant-token-attributes-size-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken rejects an `attributes` map whose total encoded size
    exceeds the documented 1 KB budget, while a small attributes map succeeds."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"), tags={"purpose": "sim2real"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    # Positive control: a small attributes map is accepted and echoed back.
    ok = ivsrt.create_participant_token(
        stageArn=stage["arn"], attributes={"role": "host"}
    )["participantToken"]
    assert ok["attributes"] == {"role": "host"}, ok["attributes"]

    oversized = {"blob": "x" * 2000}  # well over the documented 1 KB total budget
    error = _client_error(
        lambda: ivsrt.create_participant_token(stageArn=stage["arn"], attributes=oversized)
    )
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == (
        "Request member: attributes failed to satisfy the constraints: "
        "attributes is required to have a maximum size of 1 KB, found 2011 bytes"
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
