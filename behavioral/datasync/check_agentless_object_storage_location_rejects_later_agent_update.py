"""agentless-object-storage-location-rejects-later-agent-update."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "agentless-object-storage-location-rejects-later-agent-update"
GROUP = "agent-validation"
SERVICES = ["datasync"]


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A location created without an agent is locked into agentless mode: UpdateLocationObjectStorage
    refuses to attach one later, even though CreateLocationObjectStorage accepts AgentArns up front.
    """
    ds = ctx.client("datasync")
    bucket = ctx.unique_name("sim2real-behav-dsobjs-")
    loc_arn = ds.create_location_object_storage(
        ServerHostname="objs.sim2real.invalid", BucketName=bucket,
        Tags=[{"Key": "sim2real", "Value": bucket}],
    )["LocationArn"]
    ctx.on_cleanup(_teardown(lambda: ds.delete_location(LocationArn=loc_arn), "InvalidRequestException"))

    fake_agent_arn = f"arn:aws:datasync:{ctx.region}:{ctx.account}:agent/agent-{uuid.uuid4().hex[:17]}"
    code, message = _error(
        lambda: ds.update_location_object_storage(LocationArn=loc_arn, AgentArns=[fake_agent_arn])
    )
    assert code == "InvalidRequestException", (
        f"attaching an agent to an agentless location failed with {code!r}, expected 'InvalidRequestException'"
    )
    expected = "Invalid parameter: Updating AgentArns is not permitted for agentless object storage locations."
    assert message == expected, f"the refusal said {message!r}, expected {expected!r}"

    unaffected = ds.describe_location_object_storage(LocationArn=loc_arn)
    assert "AgentArns" not in unaffected, (
        f"the refused update still attached agents: {unaffected.get('AgentArns')!r}"
    )

    # Positive control: updating a different field on the SAME agentless location succeeds, so
    # the refusal above is about AgentArns specifically, not a general inability to update it.
    ds.update_location_object_storage(LocationArn=loc_arn, Subdirectory="/moved/")
    moved = ds.describe_location_object_storage(LocationArn=loc_arn)
    assert moved["LocationUri"] == f"object-storage://objs.sim2real.invalid/{bucket}/moved/", (
        f"updating Subdirectory on the same agentless location produced URI {moved['LocationUri']!r}"
    )



def _error(fn) -> tuple:
    """Return the (code, message) of the AWS error ``fn`` raises; raise if the call succeeds."""
    try:
        fn()
    except Exception as exc:
        error = getattr(exc, "response", {}).get("Error", {})
        code = error.get("Code")
        if code is None:
            raise AssertionError(f"exception carried no AWS error code: {exc!r}") from exc
        return code, error.get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code to read")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
