"""create-app-instance-user-duplicate-id-conflict-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-instance-user-duplicate-id-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateAppInstanceUser with an existing AppInstanceUserId fails with ConflictException "The resource
    that you are trying to create already exists.", the original user keeps its Name, and a distinct id succeeds."""
    # chime-sdk-identity is region-restricted (us-east-1 / eu-central-1 only); pin us-east-1.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"), Metadata="", ClientRequestToken=uuid.uuid4().hex
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    user_id = ctx.unique_name("dup-user-")
    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=user_id,
        Name="original-owner",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    code, message = _error(
        lambda: client.create_app_instance_user(
            AppInstanceArn=instance_arn,
            AppInstanceUserId=user_id,
            Name="impostor-owner",
            ClientRequestToken=uuid.uuid4().hex,
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException creating a second AppInstanceUser with the already-used "
        f"id {user_id!r}, got {code!r}"
    )
    expected_message = "The resource that you are trying to create already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original user's Name was never overwritten by the rejected attempt.
    desc = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]
    assert desc["Name"] == "original-owner", (
        f"expected original-owner's Name unchanged by the rejected duplicate-id create, "
        f"got {desc['Name']!r}"
    )

    # Positive control: a distinct AppInstanceUserId still succeeds under the same AppInstance.
    other_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("other-user-"),
        Name="control-owner",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]
    other_desc = client.describe_app_instance_user(AppInstanceUserArn=other_arn)["AppInstanceUser"]
    assert other_desc["Name"] == "control-owner", (
        f"expected the distinct-id positive control to be created with Name control-owner, "
        f"got {other_desc['Name']!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ConflictException creating a duplicate-id AppInstanceUser, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
