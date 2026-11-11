"""create-app-instance-user-with-expiration-settings-at-creation."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-app-instance-user-with-expiration-settings-at-creation"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAppInstanceUser accepts ExpirationSettings inline at creation time and
    DescribeAppInstanceUser reflects the same schedule immediately."""
    # chime-sdk-identity is only published in us-east-1 and eu-central-1 (botocore
    # endpoints.json); the suite's default us-west-2 does not resolve it.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    tag_list = [{"Key": "sim2real-env", "Value": "behavioral"}]
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=tag_list,
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="pre-expiring-user",
        ClientRequestToken=uuid.uuid4().hex,
        ExpirationSettings={"ExpirationDays": 45, "ExpirationCriterion": "CREATED_TIMESTAMP"},
        Tags=tag_list,
    )["AppInstanceUserArn"]

    desc = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]
    got = desc.get("ExpirationSettings")
    assert got is not None and got["ExpirationDays"] == 45, (
        f"expected ExpirationDays=45 set at creation, describe returned {got!r}"
    )
    assert got["ExpirationCriterion"] == "CREATED_TIMESTAMP", (
        f"expected ExpirationCriterion=CREATED_TIMESTAMP, got {got['ExpirationCriterion']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
