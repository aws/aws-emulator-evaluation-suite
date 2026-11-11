"""describe-app-instance-bot-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-app-instance-bot-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAppInstanceBot on a well-formed but nonexistent AppInstanceBotArn fails with ForbiddenException "You
    are not allowed to make this request.", not a not-found error, no such bot is listed, and the AppInstance
    itself is describable."""
    # chime-sdk-identity's control plane is only reachable from us-east-1, even though the
    # hostname resolves elsewhere; pin it via ctx.client so both branches stay credentialed.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    fake_bot_arn = f"{instance_arn}/bot/{uuid.uuid4()}"
    error = _error(lambda: client.describe_app_instance_bot(AppInstanceBotArn=fake_bot_arn))
    assert error["Code"] == "ForbiddenException", f"expected ForbiddenException, got {error!r}"
    assert error["Message"] == "You are not allowed to make this request.", (
        f"expected the standard forbidden-request message, got {error!r}"
    )

    # Effect absent: no bot with that id shows up under the AppInstance.
    bots = client.list_app_instance_bots(AppInstanceArn=instance_arn)["AppInstanceBots"]
    assert not any(fake_bot_arn in b.get("AppInstanceBotArn", "") for b in bots), (
        f"expected no bot for {fake_bot_arn}, found one listed in {bots!r}"
    )

    # Positive control: the underlying AppInstance itself is very much describable.
    desc = client.describe_app_instance(AppInstanceArn=instance_arn)["AppInstance"]
    assert desc["AppInstanceArn"] == instance_arn, (
        f"expected positive control to describe {instance_arn}, got {desc!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected DescribeAppInstanceBot on a non-existent ARN to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
