"""get-stage-not-found-after-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-stage-not-found-after-delete"
GROUP = "state"
SERVICES = ["ivs-realtime"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    still serves the deleted stage never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteStage, the stage is gone: GetStage/ListStages no longer surface it,
    and a mutation (UpdateStage) targeting the dead ARN is rejected too."""
    ivs = ctx.client("ivs-realtime")
    arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]["arn"]

    # Positive control: the stage exists and is retrievable right after creation.
    got_arn = ivs.get_stage(arn=arn)["stage"]["arn"]
    assert got_arn == arn, f"expected GetStage to echo {arn!r}, got {got_arn!r}"

    ivs.delete_stage(arn=arn)

    code, message = _error(lambda: ivs.get_stage(arn=arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"Resource: {arn} not found", message

    update_code, update_message = _error(
        lambda: ivs.update_stage(arn=arn, name=ctx.unique_name("sim2real-stage-renamed-"))
    )
    assert update_code == "ResourceNotFoundException", update_code
    assert update_message == f"Resource: {arn} not found", update_message

    arns = [s["arn"] for s in ivs.list_stages()["stages"]]
    assert arn not in arns, f"deleted stage {arn!r} still present in ListStages: {arns!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
