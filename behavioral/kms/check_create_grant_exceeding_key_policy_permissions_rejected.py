"""create-grant-exceeding-key-policy-permissions-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-grant-exceeding-key-policy-permissions-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]
SESSION_NAME = "sim2real-kms-session"
MSG_DENIED = (
    "User: arn:aws:sts::{account}:assumed-role/{role_name}/{session} is not authorized to "
    "perform: kms:CreateGrant on resource: {key_arn} because no identity-based policy allows "
    "the kms:CreateGrant action"
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGrant is denied for a principal whose key policy grants kms:DescribeKey
    but omits kms:CreateGrant, proving grant-issuance authorization is checked
    independently of other permitted actions on the same key."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-kms-describe-only-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    key = kms.create_key(Description=ctx.unique_name("sim2real-kms-grant-block-"))
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowDescribeOnly",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "kms:DescribeKey",
                "Resource": "*",
            },
        ],
    }
    _poll_until(
        lambda: _put_key_policy_ok(kms, key_id, key_policy),
        lambda v: v is True,
        timeout_s=90.0,
        interval_s=3.0,
    )

    assumed_kms = _assumed_client(ctx, role_arn, kms)

    # Prove the role's permitted action works once the policy has propagated.
    _poll_until(
        lambda: assumed_kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyId"],
        lambda v: v == key_id,
        timeout_s=90.0,
        interval_s=3.0,
    )

    got = _err(
        lambda: assumed_kms.create_grant(
            KeyId=key_id, GranteePrincipal=role_arn, Operations=["Decrypt"]
        )
    )
    expected = (
        "AccessDeniedException",
        MSG_DENIED.format(
            account=account_id, role_name=role_name, session=SESSION_NAME, key_arn=key_arn
        ),
    )
    assert got == expected, (
        f"a role whose key-policy statement grants kms:DescribeKey but omits "
        f"kms:CreateGrant must have CreateGrant refused with {expected!r}; got {got!r}"
    )

    grants_after_denied = kms.list_grants(KeyId=key_id)["Grants"]
    assert not any(g["GranteePrincipal"] == role_arn for g in grants_after_denied), (
        f"the denied create_grant call must have no effect: {role_arn} must not appear as a "
        f"grantee in an independent list_grants read; got {grants_after_denied!r}"
    )

    # Restore: grant the SAME role kms:CreateGrant on the same key policy, then retry the
    # IDENTICAL call as the SAME principal. A positive control by the key owner would only
    # prove CreateGrant works on this key in general -- it cannot distinguish "denied for
    # lacking kms:CreateGrant" from "denied for being this role, full stop". Re-authorizing
    # this exact role and replaying its exact call is what actually isolates the permission.
    key_policy["Statement"][1]["Action"] = ["kms:DescribeKey", "kms:CreateGrant"]
    _poll_until(
        lambda: _put_key_policy_ok(kms, key_id, key_policy),
        lambda v: v is True,
        timeout_s=90.0,
        interval_s=3.0,
    )

    grant = _retry_on_access_denied(
        lambda: assumed_kms.create_grant(
            KeyId=key_id, GranteePrincipal=role_arn, Operations=["Decrypt"]
        )
    )
    ctx.on_cleanup(lambda gid=grant["GrantId"]: kms.revoke_grant(KeyId=key_id, GrantId=gid))

    grants_now = kms.list_grants(KeyId=key_id)["Grants"]
    assert any(g["GrantId"] == grant["GrantId"] for g in grants_now), (
        f"restoring kms:CreateGrant for {role_arn} must let the identical create_grant call "
        f"the role previously issued now succeed and show up on an independent list_grants "
        f"read; got grant ids {[g['GrantId'] for g in grants_now]!r}"
    )


def _put_key_policy_ok(kms, key_id, key_policy):
    """PutKeyPolicy validates that every principal ARN in the policy currently
    resolves via IAM; a role created moments ago can trip
    MalformedPolicyDocumentException until IAM propagation catches up. Retry the
    call itself (not just downstream reads) until it is accepted."""
    from botocore.exceptions import ClientError

    try:
        kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(key_policy))
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "MalformedPolicyDocumentException":
            return False
        raise
    return True

def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _retry_on_access_denied(fn, timeout_s=90.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "AccessDeniedException":
                raise
            last = code
            time.sleep(interval_s)
    raise AssertionError(
        f"call kept failing with AccessDeniedException after {timeout_s}s despite the "
        f"restored kms:CreateGrant permission (last={last!r})"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            val = probe()
        except Exception as exc:  # noqa: BLE001 - transient IAM/KMS propagation lag
            last = exc
            time.sleep(interval_s)
            continue
        if predicate(val):
            return val
        last = val
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _assumed_client(ctx, role_arn, base_client):
    sts = ctx.client("sts")

    def _try_assume():
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=SESSION_NAME)
        return resp["Credentials"]

    creds = _poll_until(_try_assume, lambda c: c is not None, timeout_s=30.0, interval_s=2.0)
    return ctx.client(
        "kms",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
