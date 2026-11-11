"""delete-stage-not-found-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-stage-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStage on an ARN that doesn't reference an existing stage is rejected with
    ResourceNotFoundException, while deleting a real stage still succeeds (and the deleted
    stage genuinely disappears)."""
    ivsrt = ctx.client("ivs-realtime")
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{ctx.account}:stage/{uuid.uuid4().hex[:12]}"

    error = _client_error(lambda: ivsrt.delete_stage(arn=bogus_arn))
    assert error.get("Code") == "ResourceNotFoundException", error
    assert error.get("Message") == f"Resource: {bogus_arn} not found", error

    stage = ivsrt.create_stage(name=ctx.unique_name("sim2real-ivsrt-stage-"))["stage"]
    ivsrt.delete_stage(arn=stage["arn"])

    gone = _client_error(lambda: ivsrt.get_stage(arn=stage["arn"]))
    assert gone.get("Code") == "ResourceNotFoundException", gone
    assert gone.get("Message") == f"Resource: {stage['arn']} not found", gone


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
