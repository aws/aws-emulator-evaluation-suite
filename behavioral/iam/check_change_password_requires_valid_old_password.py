"""change-password-requires-valid-old-password."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-password-requires-valid-old-password"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ChangePassword with a wrong OldPassword is rejected with AccessDenied and changes nothing:
    a later change using the true current password still succeeds."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-cp-oldpw-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": "change-password-requires-valid-old-password"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
    iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        )
    )

    p0 = "Sim2Real!OldPw-First1"
    iam.create_login_profile(UserName=user_name, Password=p0, PasswordResetRequired=False)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.delete_login_profile(UserName=user_name))
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    user_iam = _wait_for_usable_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])

    # Positive control: the correct old password succeeds.
    p1 = "Sim2Real!OldPw-Second2"
    _change_password_with_propagation_retry(user_iam, p0, p1)

    # Break exactly one thing: p0 is no longer the current password, so it is now a
    # WRONG old password.
    code, message = _error(
        lambda: user_iam.change_password(OldPassword=p0, NewPassword="Sim2Real!OldPw-Bogus9")
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}: {message}"
    # The exact text separates "wrong old password" from a blanket permission denial: the
    # IAMUserChangePassword policy is attached and the positive control above just proved
    # this exact caller/action pair is otherwise authorized.
    assert message == (
        "Either the new password does not conform to the account password policy "
        "or the old password was incorrect."
    ), f"wrong-old-password ChangePassword message: {message!r}"

    # Effect absent, and the identical call now succeeds: this can only work if the real
    # current password is still p1, i.e. the rejected call above never mutated it.
    p2 = "Sim2Real!OldPw-Third3"
    user_iam.change_password(OldPassword=p1, NewPassword=p2)

    profile = iam.get_login_profile(UserName=user_name)["LoginProfile"]
    assert profile["UserName"] == user_name


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected change_password to be rejected, but it succeeded")


def _wait_for_usable_credentials(ctx, access_key_id, secret_access_key, timeout_s=120.0):
    """Poll until a new access key authenticates; GetUser AccessDenied counts as recognized.

    The user holds only IAMUserChangePassword, so GetUser itself is never expected to succeed.
    """
    from botocore.exceptions import ClientError

    creds = {"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key}
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        client = ctx.client("iam", creds=creds)
        try:
            client.get_user()
            return client
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return client
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"new access key never became usable within {timeout_s}s: {last_exc}")


def _change_password_with_propagation_retry(client, old_password, new_password, timeout_s=120.0):
    """Retry ChangePassword while the new key is still unknown to it.

    A key GetUser already recognizes can still get InvalidClientTokenId from ChangePassword.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            client.change_password(OldPassword=old_password, NewPassword=new_password)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                raise
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"new access key never became usable for ChangePassword within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
