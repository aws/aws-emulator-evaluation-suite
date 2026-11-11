"""expiration-settings-set-and-clear."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "expiration-settings-set-and-clear"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAppInstanceUserExpirationSettings sets an expiration schedule that is reflected in
    DescribeAppInstanceUser; calling it again with no ExpirationSettings clears the schedule."""
    # chime-sdk-identity's control plane is us-east-1 only.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="expiring-user",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceUserArn"]

    put_resp = client.put_app_instance_user_expiration_settings(
        AppInstanceUserArn=user_arn,
        ExpirationSettings={"ExpirationDays": 10, "ExpirationCriterion": "CREATED_TIMESTAMP"},
    )
    assert put_resp["ExpirationSettings"]["ExpirationDays"] == 10, (
        f"expected PutAppInstanceUserExpirationSettings to echo ExpirationDays=10, "
        f"got {put_resp.get('ExpirationSettings')}"
    )

    desc = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]
    assert desc["ExpirationSettings"]["ExpirationDays"] == 10, (
        f"expected DescribeAppInstanceUser to reflect ExpirationDays=10, "
        f"got {desc.get('ExpirationSettings')}"
    )
    assert desc["ExpirationSettings"]["ExpirationCriterion"] == "CREATED_TIMESTAMP", (
        f"expected ExpirationCriterion=CREATED_TIMESTAMP, got {desc.get('ExpirationSettings')}"
    )

    clear_resp = client.put_app_instance_user_expiration_settings(AppInstanceUserArn=user_arn)
    assert "ExpirationSettings" not in clear_resp, (
        f"expected clearing PutAppInstanceUserExpirationSettings to omit ExpirationSettings, "
        f"got {clear_resp.get('ExpirationSettings')}"
    )

    desc_after = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]
    assert "ExpirationSettings" not in desc_after, (
        f"expected DescribeAppInstanceUser to show the schedule cleared, "
        f"got {desc_after.get('ExpirationSettings')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
