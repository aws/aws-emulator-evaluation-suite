"""agent-not-found-error-is-consistent-across-location-types."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "agent-not-found-error-is-consistent-across-location-types"
GROUP = "agent-validation"
SERVICES = ["datasync"]


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A syntactically valid but unregistered agent ARN is refused identically by DescribeAgent
    and by every Create*Location call that names it in AgentArns, regardless of location family.
    """
    ds = ctx.client("datasync")
    agent_id = f"agent-{uuid.uuid4().hex[:17]}"
    agent_arn = f"arn:aws:datasync:{ctx.region}:{ctx.account}:agent/{agent_id}"

    describe_code, describe_message = _error(lambda: ds.describe_agent(AgentArn=agent_arn))
    assert describe_code == "InvalidRequestException", (
        f"DescribeAgent for an unregistered agent failed with {describe_code!r}, "
        "expected 'InvalidRequestException'"
    )
    expected = f"{agent_id} does not exist or has been deleted."
    assert describe_message == expected, (
        f"DescribeAgent said {describe_message!r}, expected {expected!r}"
    )

    nfs_code, nfs_message = _error(lambda: ds.create_location_nfs(
        Subdirectory="/export", ServerHostname="nfs.sim2real.invalid",
        OnPremConfig={"AgentArns": [agent_arn]},
    ))
    hdfs_code, hdfs_message = _error(lambda: ds.create_location_hdfs(
        NameNodes=[{"Hostname": "hdfs.sim2real.invalid", "Port": 8020}],
        AuthenticationType="SIMPLE", SimpleUser="hadoop", AgentArns=[agent_arn],
    ))
    smb_code, smb_message = _error(lambda: ds.create_location_smb(
        Subdirectory="/share", ServerHostname="smb.sim2real.invalid",
        User="guest", Password="sim2real-not-a-real-secret", AgentArns=[agent_arn],
    ))

    for name, code, message in (
        ("CreateLocationNfs", nfs_code, nfs_message),
        ("CreateLocationHdfs", hdfs_code, hdfs_message),
        ("CreateLocationSmb", smb_code, smb_message),
    ):
        assert code == "InvalidRequestException", (
            f"{name} with the unregistered agent failed with {code!r}, expected 'InvalidRequestException'"
        )
        assert message == expected, f"{name} said {message!r}, expected {expected!r} (same as DescribeAgent)"

    # Positive control: the same AgentArns member, dropped entirely, does not make
    # CreateLocationObjectStorage fail at all — the refusal above is about THIS agent, not the shape.
    bucket = ctx.unique_name("sim2real-behav-dsobjs-")
    loc_arn = ds.create_location_object_storage(
        ServerHostname="objs.sim2real.invalid", BucketName=bucket,
        Tags=[{"Key": "sim2real", "Value": bucket}],
    )["LocationArn"]
    ctx.on_cleanup(_teardown(lambda: ds.delete_location(LocationArn=loc_arn), "InvalidRequestException"))
    described = ds.describe_location_object_storage(LocationArn=loc_arn)
    assert described["LocationArn"] == loc_arn, (
        f"the agentless control location describes as {described['LocationArn']!r}, expected {loc_arn!r}"
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
