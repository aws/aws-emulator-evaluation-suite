"""delete-app-instance-admin-demotes."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-instance-admin-demotes"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteAppInstanceAdmin the user is absent from ListAppInstanceAdmins, DescribeAppInstanceAdmin fails with
    ForbiddenException "You are not allowed to make this request.", a second delete succeeds, and the user still
    exists and can be promoted again."""
    # chime-sdk-identity is only served from us-east-1 and eu-central-1 (identity-chime is
    # absent from every other partition endpoint), so the control-plane region must be pinned.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"), Metadata="", ClientRequestToken=uuid.uuid4().hex
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))
    client.tag_resource(ResourceARN=instance_arn, Tags=[{"Key": "sim2real-env", "Value": "behavioral"}])

    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="demoted-admin",
        ClientRequestToken=uuid.uuid4().hex,
    )["AppInstanceUserArn"]

    client.create_app_instance_admin(AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn)
    admins_before = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert any(a["Admin"]["Arn"] == user_arn for a in admins_before), (
        f"expected {user_arn} in ListAppInstanceAdmins before demotion, got {admins_before}"
    )

    client.delete_app_instance_admin(AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn)

    admins_after = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert not any(a["Admin"]["Arn"] == user_arn for a in admins_after), (
        f"expected {user_arn} absent from ListAppInstanceAdmins after demotion, got {admins_after}"
    )

    # AWS answers a demoted identity's DescribeAppInstanceAdmin with ForbiddenException, not
    # NotFoundException -- Chime models "no such admin grant" as an authorization refusal rather
    # than a missing-resource one.
    describe_code, describe_message = _error(
        lambda: client.describe_app_instance_admin(
            AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn
        )
    )
    assert describe_code == "ForbiddenException", (
        f"expected ForbiddenException from DescribeAppInstanceAdmin on a demoted identity, "
        f"got {describe_code}"
    )
    assert describe_message == "You are not allowed to make this request.", (
        f"expected the exact ForbiddenException message, got {describe_message!r}"
    )

    # Re-demoting an already-demoted identity is idempotent on AWS -- it succeeds rather than
    # raising ConflictException.
    client.delete_app_instance_admin(AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn)
    admins_still_absent = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert not any(a["Admin"]["Arn"] == user_arn for a in admins_still_absent), (
        f"expected {user_arn} to remain absent after an idempotent re-demote, got {admins_still_absent}"
    )

    # The user itself was NOT deleted by demotion.
    desc = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]
    assert desc["AppInstanceUserArn"] == user_arn, (
        f"expected {user_arn} to still describe after demotion, got {desc}"
    )
    assert desc["Name"] == "demoted-admin", f"expected Name preserved, got {desc.get('Name')!r}"

    # The identity is reusable: it can be promoted again, proving the earlier grant was revoked
    # rather than the identity itself being banned from admin status.
    client.create_app_instance_admin(AppInstanceAdminArn=user_arn, AppInstanceArn=instance_arn)
    admins_repromoted = client.list_app_instance_admins(AppInstanceArn=instance_arn)["AppInstanceAdmins"]
    assert any(a["Admin"]["Arn"] == user_arn for a in admins_repromoted), (
        f"expected {user_arn} reusable as admin after demotion, got {admins_repromoted}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
