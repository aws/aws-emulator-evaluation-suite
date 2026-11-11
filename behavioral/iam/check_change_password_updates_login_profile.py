"""change-password-updates-login-profile."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-password-updates-login-profile"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangePassword mutates the caller's own login profile without the admin UpdateLoginProfile path."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-chpw-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # By default an IAM user has no permission to call the self-service
    # ChangePassword API at all -- there is no implicit "manage my own
    # password" grant analogous to the console's "allow users to change
    # their own password" account setting. The AWS-managed
    # IAMUserChangePassword policy is exactly the permission AWS documents
    # for enabling this self-service call, so attach it before exercising
    # ChangePassword from the user's own credentials.
    change_password_policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
    iam.attach_user_policy(UserName=user_name, PolicyArn=change_password_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=change_password_policy_arn)
        )
    )

    old_password = "Sim2Real!ChPw-First1"
    iam.create_login_profile(UserName=user_name, Password=old_password, PasswordResetRequired=False)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.delete_login_profile(UserName=user_name))
    )

    created_profile = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    created_at = created_profile["CreateDate"]

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    user_iam = ctx.client(
        "iam",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    new_password = "Sim2Real!ChPw-Second2"
    _change_password_with_propagation_retry(user_iam, old_password, new_password)

    # If the mutation from ChangePassword did not actually persist, this second
    # self-service change (using the *new* password as OldPassword) would be
    # rejected because the account's real current password would still be the
    # original one.
    third_password = "Sim2Real!ChPw-Third3"
    user_iam.change_password(OldPassword=new_password, NewPassword=third_password)

    # The login profile itself is untouched by the admin UpdateLoginProfile path and
    # remains visible/active the whole time: same identity, same CreateDate (mutated
    # in place rather than deleted and recreated), and the reset flag it was created
    # with is not disturbed by two self-service password changes.
    profile = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    assert profile["UserName"] == user_name, f"expected {user_name!r}, got {profile['UserName']!r}"
    assert profile["CreateDate"] == created_at, (
        f"login profile CreateDate changed from {created_at!r} to {profile['CreateDate']!r} "
        "after self-service password changes -- implies delete+recreate, not in-place mutation"
    )
    assert profile["PasswordResetRequired"] is False, (
        f"expected PasswordResetRequired to remain False, got {profile['PasswordResetRequired']!r}"
    )


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _change_password_with_propagation_retry(client, old_password, new_password, timeout_s=120.0):
    """New IAM access keys take a moment to propagate; retry the real call, not a proxy for it.

    On real AWS this propagation delay is occasionally well beyond the ~10s typically quoted
    in docs. A separate GetUser call is not a usable readiness probe: GetUser can come back
    AccessDenied (recognized signature, no permission) while the
    *same* key still gets InvalidClientTokenId from ChangePassword moments later, so propagation
    is not a single account-wide switch that flips for all IAM calls at once. Retrying the actual
    call this check depends on is the only faithful probe of it.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            client.change_password(OldPassword=old_password, NewPassword=new_password)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                raise
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"new access key never became usable within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
