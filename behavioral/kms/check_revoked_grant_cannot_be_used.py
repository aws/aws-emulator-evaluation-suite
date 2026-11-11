"""revoked-grant-cannot-be-used."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoked-grant-cannot-be-used"
GROUP = "overly-permissive"
SERVICES = ["kms"]
_SESSION_NAME = "sim2real-session"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After RevokeGrant succeeds, the revoked grant token can no longer authorize Decrypt."""
    kms = ctx.client("kms")
    key_id = _create_symmetric_key(ctx)
    role_arn = _create_zero_permission_role(ctx)
    creds = _assume_role_creds(ctx, role_arn)
    role_kms = _client_with_creds(ctx, "kms", creds)

    plaintext = b"revoked-grant-test-payload"
    encrypted = kms.encrypt(KeyId=key_id, Plaintext=plaintext)
    ciphertext = encrypted["CiphertextBlob"]

    grant = kms.create_grant(KeyId=key_id, GranteePrincipal=role_arn, Operations=["Decrypt"])
    grant_token = grant["GrantToken"]
    grant_id = grant["GrantId"]

    # positive (fast path): the grant token itself proves authorization immediately,
    # bypassing the eventual-consistency propagation delay of the grant itself.
    decrypted = _retry_on_access_denied(
        lambda: role_kms.decrypt(CiphertextBlob=ciphertext, GrantTokens=[grant_token])
    )["Plaintext"]
    assert decrypted == plaintext

    # confirm the grant has *also* propagated through the normal (non-token) lookup path --
    # this establishes a same-path baseline so the post-revocation check below is measuring
    # the effect of revocation, not residual propagation lag of the grant itself.
    def probe_allowed():
        return _outcome(lambda: role_kms.decrypt(CiphertextBlob=ciphertext))

    baseline = _poll_until(probe_allowed, lambda c: c["Code"] == "OK", timeout_s=90.0)
    assert baseline["Code"] == "OK", baseline

    kms.revoke_grant(KeyId=key_id, GrantId=grant_id)

    # negative: after revocation, plain (non-token) Decrypt for the grantee is denied again
    # (poll for the transition -- grant revocation can take a short while to become globally
    # effective, same as grant creation does)
    def probe_denied():
        return _outcome(lambda: role_kms.decrypt(CiphertextBlob=ciphertext))

    denied = _poll_until(probe_denied, lambda c: c["Code"] == "AccessDeniedException", timeout_s=90.0)
    assert denied["Code"] == "AccessDeniedException", denied
    expected = _no_identity_policy_message(role_arn, encrypted["KeyId"])
    assert denied["Message"] == expected, f"expected message {expected!r}, got {denied['Message']!r}"
    # effect absent: no plaintext is returned by the revoked grant's grantee any more

    # positive control: a brand-new grant still lets the role decrypt the very same ciphertext
    grant2 = kms.create_grant(KeyId=key_id, GranteePrincipal=role_arn, Operations=["Decrypt"])
    token2 = grant2["GrantToken"]
    ctx.on_cleanup(lambda: kms.retire_grant(GrantToken=token2))
    decrypted2 = _retry_on_access_denied(
        lambda: role_kms.decrypt(CiphertextBlob=ciphertext, GrantTokens=[token2])
    )["Plaintext"]
    assert decrypted2 == plaintext


def _outcome(fn):
    """The AWS error on failure, else ``{"Code": "OK"}`` (a value no AWS error code equals)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    return {"Code": "OK"}


def _retry_on_access_denied(fn, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"call kept failing with AccessDeniedException: {last_exc}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_symmetric_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-kms-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _create_zero_permission_role(ctx) -> str:
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kms-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _assume_role_creds(ctx, role_arn: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> dict[str, Any]:
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME, DurationSeconds=900
            )
            return resp["Credentials"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable (last error {last_code})")


def _no_identity_policy_message(role_arn: str, key_arn: str) -> str:
    """The Decrypt denial KMS returns to the role's session when no grant or policy allows it."""
    account, role_name = role_arn.split(":")[4], role_arn.split("/")[-1]
    return (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: kms:Decrypt on resource: {key_arn} because no identity-based "
        f"policy allows the kms:Decrypt action"
    )


def _client_with_creds(ctx, service: str, creds: dict[str, Any]):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
