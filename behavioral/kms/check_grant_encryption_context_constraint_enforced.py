"""grant-encryption-context-constraint-enforced."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "grant-encryption-context-constraint-enforced"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A grant with EncryptionContextEquals rejects use when the caller's context does not match."""
    kms = ctx.client("kms")
    key_id = _create_symmetric_key(ctx)
    role_arn = _create_zero_permission_role(ctx)
    creds = _assume_role_creds(ctx, role_arn)
    role_kms = _client_with_creds(ctx, "kms", creds)

    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=role_arn,
        Operations=["Encrypt"],
        Constraints={"EncryptionContextEquals": {"purpose": "invoice"}},
    )
    token = grant["GrantToken"]
    ctx.on_cleanup(lambda: kms.retire_grant(GrantToken=token))

    plaintext = b"context-constrained-payload"

    # prove the grant is live using a matching encryption context (retry while it propagates)
    ciphertext = _retry_on_access_denied(
        lambda: role_kms.encrypt(
            KeyId=key_id,
            Plaintext=plaintext,
            EncryptionContext={"purpose": "invoice"},
            GrantTokens=[token],
        )
    )["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, EncryptionContext={"purpose": "invoice"})["Plaintext"]
    assert decrypted == plaintext, f"positive control round-trip mismatch: expected {plaintext!r}, got {decrypted!r}"

    # negative: the grant is now known-live, so a mismatched context must be denied for the constraint,
    # not for propagation-lag reasons
    code, message = _error(
        lambda: role_kms.encrypt(
            KeyId=key_id,
            Plaintext=plaintext,
            EncryptionContext={"purpose": "wrong-department"},
            GrantTokens=[token],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for mismatched context, got {code!r}"
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    assert message == (
        f"User: {_session_arn(role_arn, _SESSION_NAME)} is not authorized to perform: kms:Encrypt "
        f"on resource: {key_arn} because no identity-based policy allows the kms:Encrypt action"
    ), f"unexpected message: {message!r}"
    # effect absent: the mismatched call raised before any CiphertextBlob was produced

    # positive control: the very same grant, called again with the correct context, still works
    ciphertext2 = role_kms.encrypt(
        KeyId=key_id,
        Plaintext=plaintext,
        EncryptionContext={"purpose": "invoice"},
        GrantTokens=[token],
    )["CiphertextBlob"]
    decrypted2 = kms.decrypt(CiphertextBlob=ciphertext2, EncryptionContext={"purpose": "invoice"})["Plaintext"]
    assert decrypted2 == plaintext, f"post-restore round-trip mismatch: expected {plaintext!r}, got {decrypted2!r}"


_SESSION_NAME = "sim2real-session"


def _session_arn(role_arn: str, session_name: str) -> str:
    """The assumed-role session ARN STS issues for role_arn under session_name."""
    account, role_path = role_arn.split(":")[4], role_arn.split(":")[5]
    return f"arn:aws:sts::{account}:assumed-role/{role_path.split('/')[-1]}/{session_name}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDeniedException, but the call succeeded: {result!r}")


_PROPAGATION_LAG_CODES = ("AccessDeniedException", "UnrecognizedClientException", "InvalidClientTokenId")


def _retry_on_access_denied(fn, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Retry only on the propagation-lag signature of a just-assumed role (the grant not yet visible
    to KMS, or the temporary credentials not yet recognized) — never on any other error."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _PROPAGATION_LAG_CODES:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"call kept failing with a propagation-lag error: {last_exc}")


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
