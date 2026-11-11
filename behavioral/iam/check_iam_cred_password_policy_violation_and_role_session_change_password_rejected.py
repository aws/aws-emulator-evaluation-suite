"""iam-cred-password-policy-violation-and-role-session-change-password-rejected."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-cred-password-policy-violation-and-role-session-change-password-rejected"
GROUP = "deep-iam-2-credential-policy"
SERVICES = ["iam"]

# The strict policy this check enforces. AllowUsersToChangePassword is part of it so the IAM
# user's own ChangePassword is permitted by the policy itself, not only by an IAM grant.
_STRICT = dict(
    MinimumPasswordLength=24,
    RequireSymbols=True,
    RequireNumbers=True,
    RequireUppercaseCharacters=True,
    RequireLowercaseCharacters=True,
    AllowUsersToChangePassword=True,
    PasswordReusePrevention=3,
    HardExpiry=False,
)


def _violations(p_short, p_nosym):
    """(password, why, exact PasswordPolicyViolation message) under the strict policy."""
    return (
        (p_short, "23 chars", "Password should have a minimum length of 24"),
        (p_nosym, "no symbol", "Password should have at least one symbol"),
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-password-policy")
def run(ctx) -> None:
    """The account password policy is enforced on CreateLoginProfile, UpdateLoginProfile and
    ChangePassword (length, symbol, reuse) without altering the credential; relaxing one field
    admits the password, and an assumed-role session's ChangePassword fails with InvalidUserType.
    """
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    # ---- 1. snapshot the account-global policy and register its restore BEFORE changing it ----
    # The policy is an account-global singleton, so concurrent runs in one account would conflict.
    original = _capture_password_policy(iam)
    ctx.on_cleanup(lambda: _apply_password_policy(iam, original))

    # ---- 2. strict policy, read back ----
    iam.update_account_password_policy(**_STRICT)
    applied = iam.get_account_password_policy()["PasswordPolicy"]
    assert applied["MinimumPasswordLength"] == 24, f"strict policy not stored: {applied!r}"
    assert applied.get("PasswordReusePrevention") == 3, f"reuse prevention not stored: {applied!r}"

    # ---- the throwaway user and its self-service grant ----
    user = ctx.unique_name("sim2real-iamcred-")
    user_arn = iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))

    role = ctx.unique_name("sim2real-iamcred-role-")
    account = sts.get_caller_identity()["Account"]
    partition = user_arn.split(":")[1]
    role_arn = f"arn:{partition}:iam::{account}:role/{role}"

    iam.put_user_policy(
        UserName=user,
        PolicyName="self-service",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["iam:ChangePassword", "iam:GetAccountPasswordPolicy"],
                     "Resource": "*"},
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role_arn},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_user_policy(UserName=user, PolicyName="self-service")))

    p_short = _pw(23)                    # compliant in every class, one char short
    p_nosym = _pw(24, symbol=False)      # long enough, no symbol
    p1, p2, p4, p5 = _pw(24), _pw(24), _pw(24), _pw(24)

    # ---- 3. CreateLoginProfile under the strict policy: both violations, nothing created ----
    # Registered before the negatives: a target that wrongly ACCEPTS one creates a profile, and
    # DeleteUser then fails with DeleteConflict unless the profile is removed first.
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_login_profile(UserName=user)))
    for bad, why, violation in _violations(p_short, p_nosym):
        err = _client_error(lambda: iam.create_login_profile(UserName=user, Password=bad, PasswordResetRequired=False))
        assert err.get("Code") == "PasswordPolicyViolation", (
            f"CreateLoginProfile with a password of {why} must be PasswordPolicyViolation, got {err!r}"
        )
        assert err.get("Message") == violation, (
            f"CreateLoginProfile ({why}) message: expected {violation!r}, got {err.get('Message')!r}"
        )
        absent = _client_error(lambda: iam.get_login_profile(UserName=user))
        assert absent.get("Code") == "NoSuchEntity", (
            f"a rejected CreateLoginProfile ({why}) must create no profile; GetLoginProfile gave {absent!r}"
        )
        no_profile = f"Login Profile for User {user} cannot be found."
        assert absent.get("Message") == no_profile, (
            f"GetLoginProfile NoSuchEntity message: expected {no_profile!r}, got {absent.get('Message')!r}"
        )

    # ---- 4. compliant CreateLoginProfile succeeds and reads back ----
    iam.create_login_profile(UserName=user, Password=p1, PasswordResetRequired=False)
    profile = iam.get_login_profile(UserName=user)["LoginProfile"]
    assert profile["UserName"] == user, f"GetLoginProfile returned another user: {profile!r}"
    created_at = profile["CreateDate"]

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    user_creds = {"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]}

    # ---- 5. UpdateLoginProfile under the strict policy: both violations, nothing applied ----
    for bad, why, violation in _violations(p_short, p_nosym):
        err = _client_error(lambda: iam.update_login_profile(UserName=user, Password=bad))
        assert err.get("Code") == "PasswordPolicyViolation", (
            f"UpdateLoginProfile with a password of {why} must be PasswordPolicyViolation, got {err!r}"
        )
        assert err.get("Message") == violation, (
            f"UpdateLoginProfile ({why}) message: expected {violation!r}, got {err.get('Message')!r}"
        )
        after = iam.get_login_profile(UserName=user)["LoginProfile"]["CreateDate"]
        assert after == created_at, (
            f"a rejected UpdateLoginProfile ({why}) moved CreateDate {created_at!r} -> {after!r}"
        )

    # The user's own credentials prove P1 is still the live password: ChangePassword verifies
    # OldPassword, so this succeeds only if neither rejected update replaced it.
    user_iam = _wait_for_change_password(ctx, user_creds, p1, p2)

    # ---- 6. positive control: relax ONLY the length, retry the identical 23-char password ----
    # One field is relaxed rather than restoring the snapshot, whose contents are account state.
    relaxed = dict(_STRICT, MinimumPasswordLength=23)
    iam.update_account_password_policy(**relaxed)
    assert iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"] == 23, (
        "relaxed policy not stored"
    )
    iam.update_login_profile(UserName=user, Password=p_short)
    assert iam.get_login_profile(UserName=user)["LoginProfile"]["CreateDate"] == created_at, (
        "UpdateLoginProfile must not recreate the profile"
    )

    # ---- 7. strict again; reuse of a password inside the last 3 is refused ----
    iam.update_account_password_policy(**_STRICT)
    assert iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"] == 24, (
        "strict policy not re-applied"
    )
    err = _client_error(lambda: _settled(lambda: user_iam.change_password(OldPassword=p_short, NewPassword=p1)))
    assert err.get("Code") == "PasswordPolicyViolation", (
        f"ChangePassword back to a password within the last 3 must be PasswordPolicyViolation, got {err!r}"
    )
    reused = "Password cannot be the same as previously used password"
    assert err.get("Message") == reused, (
        f"ChangePassword reuse message: expected {reused!r}, got {err.get('Message')!r}"
    )
    # Same OldPassword: succeeds only if the rejected reuse did not replace p_short.
    _settled(lambda: user_iam.change_password(OldPassword=p_short, NewPassword=p4))

    # ---- 8. an assumed-role session cannot ChangePassword: InvalidUserType ----
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"AWS": user_arn}, "Action": "sts:AssumeRole"}],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.put_role_policy(
        RoleName=role,
        PolicyName="change-password",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Action": "iam:ChangePassword", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role_policy(RoleName=role, PolicyName="change-password")))

    session = _assume_role(ctx, user_creds, role_arn)
    assert ":assumed-role/" in session["arn"], f"expected an assumed-role session, got {session['arn']!r}"
    role_iam = ctx.client("iam", creds=session["creds"])
    err = _client_error(lambda: role_iam.change_password(OldPassword=p4, NewPassword=p5))
    assert err.get("Code") == "InvalidUserType", (
        f"ChangePassword from an assumed-role session must be InvalidUserType, got {err!r}"
    )
    wrong_type = "Only IAM Users can change their own password."
    assert err.get("Message") == wrong_type, (
        f"ChangePassword InvalidUserType message: expected {wrong_type!r}, got {err.get('Message')!r}"
    )
    # Same OldPassword through the user's own identity: p4 is still live, so the role call
    # changed nothing, and ChangePassword itself works for the right caller type.
    _settled(lambda: user_iam.change_password(OldPassword=p4, NewPassword=p5))
    assert iam.get_login_profile(UserName=user)["LoginProfile"]["CreateDate"] == created_at, (
        "ChangePassword must not recreate the profile"
    )


def _pw(length, symbol=True):
    """A password of exactly `length` chars with upper, lower and digit classes, plus a symbol
    unless symbol=False. Random so no two runs share history."""
    head = "Q" + "z" + "7" + ("#" if symbol else "")
    tail = secrets.token_hex(length)[: length - len(head)]
    pw = head + tail
    assert len(pw) == length, f"password builder produced {len(pw)} chars, wanted {length}"
    return pw


def _capture_password_policy(iam):
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return None
        raise


def _apply_password_policy(iam, policy):
    """Restore the snapshotted policy exactly, or delete ours if the account had none."""
    if policy is None:
        _ignore_no_such_entity(iam.delete_account_password_policy)
        return
    kwargs = {
        k: policy[k]
        for k in (
            "MinimumPasswordLength",
            "RequireSymbols",
            "RequireNumbers",
            "RequireUppercaseCharacters",
            "RequireLowercaseCharacters",
            "AllowUsersToChangePassword",
            "MaxPasswordAge",
            "PasswordReusePrevention",
            "HardExpiry",
        )
        if k in policy
    }
    iam.update_account_password_policy(**kwargs)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises rather than becoming a
    code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_no_such_entity(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


_PROPAGATION = ("InvalidClientTokenId", "SignatureDoesNotMatch", "AccessDenied")


_KEY_REPLICATION = ("InvalidClientTokenId", "SignatureDoesNotMatch")


def _settled(fn, timeout_s=60.0):
    """Call fn() with an access key that has already authenticated once: IAM replicates a new key
    to its endpoints unevenly, so a later call can still be refused as an unknown key. Retry only
    those key-replication codes, bounded; any other error propagates unmasked."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _KEY_REPLICATION or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _wait_for_change_password(ctx, creds, old, new, timeout_s=120.0):
    """First use of a fresh access key (and its inline grant): IAM propagation exposes no
    condition to poll, so retry the real call on signature/authorization errors only, bounded.
    Any other error — including PasswordPolicyViolation — is returned to the caller unmasked."""
    client = ctx.client("iam", creds=creds)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            client.change_password(OldPassword=old, NewPassword=new)
            return client
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _PROPAGATION:
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
    raise AssertionError(f"fresh access key never authorised ChangePassword within {timeout_s}s: {last!r}")


def _assume_role(ctx, creds, role_arn, timeout_s=120.0):
    """AssumeRole as the user; a new role's trust policy (and the user's grant) propagate with no
    pollable condition, so retry AccessDenied only, bounded."""
    user_sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = user_sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-iamcred")
            c = resp["Credentials"]
            return {
                "arn": resp["AssumedRoleUser"]["Arn"],
                "creds": {
                    "aws_access_key_id": c["AccessKeyId"],
                    "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"],
                },
            }
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
    raise AssertionError(f"AssumeRole into {role_arn} never succeeded within {timeout_s}s: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
