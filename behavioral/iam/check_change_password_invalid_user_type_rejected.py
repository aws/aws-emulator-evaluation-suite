"""change-password-invalid-user-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "change-password-invalid-user-type-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ChangePassword from a caller user without a login profile fails with NoSuchEntity
    and the exact message, as does GetLoginProfile for it, while a new user with a login
    profile changes its own password."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    caller_user_name = sts.get_caller_identity()["Arn"].rsplit("/", 1)[-1]

    # Positive control: a fresh user WITH a login profile can ChangePassword normally, so
    # the ambient rejection below is attributable to the missing login profile and not to
    # ChangePassword being broken for every caller.
    control_user = ctx.unique_name("sim2real-behav-cput-")
    iam.create_user(UserName=control_user)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=control_user))

    change_password_policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
    iam.attach_user_policy(UserName=control_user, PolicyArn=change_password_policy_arn)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.detach_user_policy(UserName=control_user, PolicyArn=change_password_policy_arn)
        )
    )

    control_old_password = "Sim2Real!Ctrl-First1"
    iam.create_login_profile(
        UserName=control_user, Password=control_old_password, PasswordResetRequired=False
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(lambda: iam.delete_login_profile(UserName=control_user))
    )

    key = iam.create_access_key(UserName=control_user)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=control_user, AccessKeyId=key["AccessKeyId"])
    )
    control_iam = _wait_for_usable_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"])
    _change_password_with_propagation_retry(
        control_iam, control_old_password, "Sim2Real!Ctrl-Second2"
    )

    # The negative: the ambient caller is a real IAM User but has no login profile at
    # all, so ChangePassword has no entity to resolve the call against.
    error = _client_error(
        lambda: iam.change_password(OldPassword="Old-Passw0rd!123", NewPassword="New-Passw0rd!456")
    )
    assert error.get("Code") == "NoSuchEntity", f"expected NoSuchEntity, got {error!r}"
    missing_profile = f"Login Profile for User {caller_user_name} cannot be found."
    assert error.get("Message") == missing_profile, f"ChangePassword message: {error!r}"

    # Independent read, at the destination, through a different operation than the
    # rejected mutation: no login profile exists for the ambient caller either.
    profile_error = _client_error(lambda: iam.get_login_profile(UserName=caller_user_name))
    assert profile_error.get("Code") == "NoSuchEntity", (
        f"expected GetLoginProfile on {caller_user_name} to also report NoSuchEntity, "
        f"got {profile_error!r}"
    )
    assert profile_error.get("Message") == missing_profile, (
        f"GetLoginProfile on {caller_user_name} message: {profile_error!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    that accepts a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_usable_credentials(ctx, access_key_id, secret_access_key, timeout_s=120.0):
    """New IAM access keys take a moment to propagate; poll until they authenticate.

    On real AWS this propagation delay is occasionally well beyond the ~10s typically
    quoted in docs, so this polls with a generous bounded timeout and a modest interval
    rather than a fixed short deadline.

    The probe call itself (GetUser) is deliberately not required to *succeed*: a freshly
    created user has no attached policies, so even once the new key's signature is fully
    propagated, GetUser on it is expected to come back AccessDenied (an authorization
    decision, not a signature/propagation one). Only a signature-level rejection (e.g.
    InvalidClientTokenId/SignatureDoesNotMatch) means the key genuinely isn't usable yet
    and is worth retrying; AccessDenied already proves the key is recognized and is
    therefore usable for the self-service calls (like ChangePassword) that this check
    actually exercises.
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
    """Retry the real ChangePassword while the new key is still unknown to it.

    A GetUser AccessDenied proves the key's signature is recognized by GetUser, but the same
    key can still get InvalidClientTokenId from ChangePassword moments later, so the call this
    check depends on is the probe.
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
