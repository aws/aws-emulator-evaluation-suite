"""delete-app-instance-admin-not-admin-succeeds-as-a-noop."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-app-instance-admin-not-admin-succeeds-as-a-noop"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAppInstanceAdmin on a user that was never an admin succeeds and adds no admin, while promoting another
    user lists it as admin and demoting it removes it from ListAppInstanceAdmins."""
    # chime-sdk-identity is region-restricted (us-east-1 / eu-central-1 only); pin us-east-1.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"), Metadata="", ClientRequestToken=uuid.uuid4().hex
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    never_admin_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("never-admin-"),
        Name="never-admin",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    # AWS treats demoting a never-promoted identity as a no-op (204), though the operation
    # models ConflictException.
    client.delete_app_instance_admin(AppInstanceAdminArn=never_admin_arn, AppInstanceArn=instance_arn)

    # Effect absent: the no-op demote did not phantom-add the identity as admin.
    admins = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert not any(a["Admin"]["Arn"] == never_admin_arn for a in admins), (
        f"never-admin identity {never_admin_arn} appeared in admin list {admins!r} "
        "after a no-op demote"
    )

    # Positive control: promoting then demoting a DIFFERENT identity still works end to end,
    # with the promotion itself independently observed before the demote.
    control_user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("control-admin-"),
        Name="control-admin",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]
    client.create_app_instance_admin(AppInstanceAdminArn=control_user_arn, AppInstanceArn=instance_arn)
    admins_before = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert any(a["Admin"]["Arn"] == control_user_arn for a in admins_before), (
        f"control identity {control_user_arn} missing from admin list {admins_before!r} "
        "after a successful promote"
    )

    client.delete_app_instance_admin(AppInstanceAdminArn=control_user_arn, AppInstanceArn=instance_arn)
    admins_after = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert not any(a["Admin"]["Arn"] == control_user_arn for a in admins_after), (
        f"control identity {control_user_arn} still listed as admin {admins_after!r} "
        "after a successful demote"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
