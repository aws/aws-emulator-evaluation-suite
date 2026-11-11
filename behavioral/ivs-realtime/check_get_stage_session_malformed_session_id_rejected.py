"""get-stage-session-malformed-session-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-stage-session-malformed-session-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetStageSession rejects a sessionId that doesn't match the documented
    ^st-[a-zA-Z0-9]+$ (length 16) pattern with ValidationException, and the stage API
    is otherwise reachable and functional."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(name=ctx.unique_name("sim2real-ivsrt-stage-"))["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    malformed = _client_error(
        lambda: ivsrt.get_stage_session(stageArn=stage["arn"], sessionId="not-a-valid-id!!")
    )
    assert malformed.get("Code") == "ValidationException", malformed
    assert malformed.get("Message") == (
        "GetStageSession.sessionId does not match the required pattern ^st-[a-zA-Z0-9]+$"
    ), malformed

    # A well-formed (matches ^st-[a-zA-Z0-9]+$, length 16) but nonexistent sessionId
    # must be distinguished from the malformed case above: NotFound, not Validation.
    # A target that always answers ValidationException for GetStageSession -- even on
    # well-formed input -- would otherwise pass the malformed-input assertion above for
    # free.
    missing = _client_error(
        lambda: ivsrt.get_stage_session(stageArn=stage["arn"], sessionId="st-0000000000000")
    )
    assert missing.get("Code") == "ResourceNotFoundException", missing
    assert missing.get("Message") == 'Resource: stage session "st-0000000000000" not found', missing

    # Positive control: the stage itself is reachable and functional.
    got = ivsrt.get_stage(arn=stage["arn"])["stage"]["arn"]
    assert got == stage["arn"], f"expected {stage['arn']}, got {got}"


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
