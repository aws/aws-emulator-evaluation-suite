"""decrypt-blocked-without-kms-decrypt-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "decrypt-blocked-without-kms-decrypt-permission"
GROUP = "overly-permissive"
SERVICES = ["kms"]
_SESSION_NAME = "sim2real-kms-session"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key policy granting kms:Encrypt (but not kms:Decrypt) to a principal lets
    that principal encrypt but blocks the very same principal from decrypting --
    proving KMS enforces per-action authorization rather than blanket key access."""
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-kms-encr-only-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-decrypt-block-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
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
                "Sid": "AllowEncryptOnly",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "kms:Encrypt",
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

    assumed_kms = _assumed_client(ctx, role_arn)

    plaintext = b"sim2real-behavioral-secret"
    ciphertext = _poll_until(
        lambda: assumed_kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"],
        lambda v: v is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )

    err = _error(lambda: assumed_kms.decrypt(CiphertextBlob=ciphertext))
    assert err.get("Code") == "AccessDeniedException", (
        f"the role has no kms:Decrypt grant, so decrypting its own ciphertext must be refused "
        f"with AccessDeniedException; got {err.get('Code')!r}"
    )
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"
    expected_message = (
        f"User: {session_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        f"because no identity-based policy allows the kms:Decrypt action"
    )
    assert err.get("Message") == expected_message, (
        f"expected AccessDeniedException message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Control: the key owner (granted kms:* via the default statement) can decrypt the
    # very same ciphertext -- proving the block above is action-specific (Decrypt only)
    # on THIS role, not a broken key or an unconditional deny on the key itself.
    control = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)
    assert control["Plaintext"] == plaintext, (
        f"the key owner's kms:* grant must still decrypt the ciphertext; "
        f"expected {plaintext!r}, got {control['Plaintext']!r}"
    )

    # Restore: grant the SAME role kms:Decrypt too, and the identical call -- through the
    # SAME assumed-role session that was just denied -- must now succeed. This is the beat
    # that separates "this role is specifically blocked" from "the target ignores key
    # policy actions entirely and denies (or allows) everyone the same way".
    key_policy["Statement"][1]["Action"] = ["kms:Encrypt", "kms:Decrypt"]
    _poll_until(
        lambda: _put_key_policy_ok(kms, key_id, key_policy),
        lambda v: v is True,
        timeout_s=90.0,
        interval_s=3.0,
    )
    restored = _poll_until(
        lambda: assumed_kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"],
        lambda v: v is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert restored == plaintext, (
        f"after granting the role kms:Decrypt, the identical decrypt call through the same "
        f"assumed-role session must succeed; expected {plaintext!r}, got {restored!r}"
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

def _error(fn):
    """The captured AWS error (Code and Message). An unexpected success raises, so an
    over-permissive target fails loudly rather than being read as denied."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


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


def _assumed_client(ctx, role_arn):
    sts = ctx.client("sts")

    def _try_assume():
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
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
