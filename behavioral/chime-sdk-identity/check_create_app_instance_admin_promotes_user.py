"""create-app-instance-admin-promotes-user."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-app-instance-admin-promotes-user"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAppInstanceAdmin promotes an AppInstanceUser; the promotion is visible through both
    ListAppInstanceAdmins and DescribeAppInstanceAdmin."""
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
        Name="future-admin",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceUserArn"]

    resp = client.create_app_instance_admin(AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn)
    assert resp["AppInstanceAdmin"]["Arn"] == user_arn, (
        f"expected promoted admin arn {user_arn!r}, got {resp['AppInstanceAdmin']['Arn']!r}"
    )
    assert resp["AppInstanceArn"] == instance_arn, (
        f"expected AppInstanceArn {instance_arn!r}, got {resp['AppInstanceArn']!r}"
    )

    admins = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert any(a["Admin"]["Arn"] == user_arn for a in admins), (
        f"expected {user_arn!r} among ListAppInstanceAdmins, got {[a['Admin']['Arn'] for a in admins]!r}"
    )

    desc = client.describe_app_instance_admin(
        AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn
    )["AppInstanceAdmin"]
    assert desc["Admin"]["Arn"] == user_arn, (
        f"DescribeAppInstanceAdmin expected {user_arn!r}, got {desc['Admin']['Arn']!r}"
    )
    assert desc["AppInstanceArn"] == instance_arn, (
        f"DescribeAppInstanceAdmin expected AppInstanceArn {instance_arn!r}, got {desc['AppInstanceArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
