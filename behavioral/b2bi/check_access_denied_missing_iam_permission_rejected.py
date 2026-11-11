"""access-denied-missing-iam-permission-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-missing-iam-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]

_IAM_TAGS = [{"Key": "sim2real", "Value": "true"}]
_B2BI_TAGS = [{"Key": "sim2real", "Value": "true"}]

_ALLOW_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "b2bi:CreateProfile",
                "b2bi:GetProfile",
                "b2bi:ListProfiles",
                "b2bi:DeleteProfile",
                "b2bi:TagResource",
            ],
            "Resource": "*",
        },
    ],
}
_ALLOW_DENY_CREATE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "b2bi:CreateProfile",
                "b2bi:GetProfile",
                "b2bi:ListProfiles",
                "b2bi:DeleteProfile",
                "b2bi:TagResource",
            ],
            "Resource": "*",
        },
        {"Effect": "Deny", "Action": "b2bi:CreateProfile", "Resource": "*"},
    ],
}


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProfile under an IAM Deny is rejected with AccessDeniedException and creates nothing,
    while the same session's identical call succeeds before the Deny and after it is lifted."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    b2bi = ctx.client("b2bi")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-b2bi-toggle-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_IAM_TAGS
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "toggle-create-profile"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_ALLOW_POLICY))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    role_client = _assume_role_client(ctx, role_arn)

    profile_name = ctx.unique_name("sim2real-b2bi-toggled-profile-")
    business_name = ctx.unique_name("sim2real-b2bi-biz-")

    def _attempt():
        try:
            resp = role_client.create_profile(
                name=profile_name,
                phone="+15555550100",
                businessName=business_name,
                logging="DISABLED",
                tags=_B2BI_TAGS,
            )
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        return resp

    # --- Beat 1: positive control. The role's Allow-only policy grants CreateProfile, so the
    # account and the assumed session are otherwise healthy before anything is broken.
    control = _poll_until(
        _attempt,
        lambda r: not isinstance(r, tuple),
        timeout_s=90,
        interval_s=5,
        description="the role's Allow policy becomes effective for b2bi:CreateProfile",
    )
    assert not isinstance(control, tuple), f"expected the positive control to succeed, got error {control!r}"
    control_profile_id = control["profileId"]
    assert _profile_name_exists(ctx, profile_name), (
        f"expected positive-control profile {profile_name!r} to be visible via ListProfiles"
    )
    # Free the name for the identical calls that follow; a guarded delete since it may already
    # be gone if a later step in this function fails after deleting it again.
    _delete_profile_if_exists(b2bi, control_profile_id)

    # --- Beat 2: break exactly one thing. Add a Deny on b2bi:CreateProfile to the same inline
    # policy, leaving the Allow (and everything else the role can already do) untouched.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_ALLOW_DENY_CREATE_POLICY)
    )

    def _attempt_denied():
        result = _attempt()
        if not isinstance(result, tuple):
            # Inline-policy update hasn't propagated yet: the call went through, so undo it and
            # retry rather than let a race-won success masquerade as "the Deny never worked".
            _delete_profile_if_exists(b2bi, result["profileId"])
            return None
        return result

    # --- Beats 3+4: the specific error code, then absence via an independent read.
    code, message = _poll_until(
        _attempt_denied,
        lambda c: c is not None and c[0] == "AccessDeniedException",
        timeout_s=90,
        interval_s=5,
        description="b2bi:CreateProfile denial to take effect after the inline policy update",
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized "
        f"to perform: b2bi:CreateProfile on resource: arn:aws:b2bi:{ctx.region}:{account_id}:profile/* "
        f"with an explicit deny in an identity-based policy"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert not _profile_name_exists(ctx, profile_name), (
        f"expected no profile named {profile_name!r} to exist after the denied CreateProfile call"
    )

    # --- Beat 5: restore the Allow-only policy.
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_ALLOW_POLICY))

    # --- Beat 6: the identical call now succeeds again.
    restored = _poll_until(
        _attempt,
        lambda r: not isinstance(r, tuple),
        timeout_s=90,
        interval_s=5,
        description="b2bi:CreateProfile to succeed again after the inline policy restore",
    )
    assert not isinstance(restored, tuple), (
        f"expected the identical call to succeed once the Deny is removed, got error {restored!r}"
    )
    restored_profile_id = restored["profileId"]
    ctx.on_cleanup(lambda: _delete_profile_if_exists(b2bi, restored_profile_id))
    assert _profile_name_exists(ctx, profile_name), (
        f"expected restored profile {profile_name!r} to be visible via ListProfiles"
    )


def _poll_until(fn, pred, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _delete_profile_if_exists(b2bi, profile_id: str) -> None:
    try:
        b2bi.delete_profile(profileId=profile_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


_SESSION_NAME = "sim2real-b2bi-check"


def _assume_role_client(ctx: Any, role_arn: str):
    sts = ctx.client("sts")
    session_name = _SESSION_NAME

    deadline = time.monotonic() + 30.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except Exception as exc:  # IAM role/policy propagation delay
            last_exc = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"could not assume role in time: {last_exc}")

    return ctx.client(
        "b2bi",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _profile_name_exists(ctx: Any, name: str) -> bool:
    b2bi = ctx.client("b2bi")
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["nextToken"] = token
        page = b2bi.list_profiles(**kwargs)
        if any(p["name"] == name for p in page.get("profiles", [])):
            return True
        token = page.get("nextToken")
        if not token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
