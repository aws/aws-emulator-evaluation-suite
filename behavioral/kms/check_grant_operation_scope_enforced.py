"""grant-operation-scope-enforced."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "grant-operation-scope-enforced"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A grant issued only for Encrypt cannot be used to authorize Decrypt with the same grant token."""
    kms = ctx.client("kms")
    key_id = _create_symmetric_key(ctx)
    role_arn = _create_zero_permission_role(ctx)
    creds = _assume_role_creds(ctx, role_arn)
    role_kms = _client_with_creds(ctx, "kms", creds)

    # sanity: the role has no baseline permission to use the key at all
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    session_arn = _session_arn(role_arn, _SESSION_NAME)
    baseline_code, baseline_message = _error(lambda: role_kms.encrypt(KeyId=key_id, Plaintext=b"probe"))
    assert baseline_code == "AccessDeniedException", (
        f"expected AccessDeniedException with no grant issued yet, got {baseline_code!r}"
    )
    assert baseline_message == (
        f"User: {session_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        f"because no identity-based policy allows the kms:Encrypt action"
    ), f"unexpected message: {baseline_message!r}"

    grant = kms.create_grant(KeyId=key_id, GranteePrincipal=role_arn, Operations=["Encrypt"])
    grant_token = grant["GrantToken"]
    ctx.on_cleanup(lambda: kms.retire_grant(GrantToken=grant_token))

    plaintext = b"grant-scope-test-payload"
    # positive: the grant genuinely authorizes Encrypt (retry while the grant propagates)
    ciphertext = _retry_on_access_denied(
        lambda: role_kms.encrypt(KeyId=key_id, Plaintext=plaintext, GrantTokens=[grant_token])
    )["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected {plaintext!r} back from an independent Decrypt, got {decrypted!r}"

    # negative: the SAME grant token cannot authorize Decrypt (only Encrypt was granted)
    code, message = _error(lambda: role_kms.decrypt(CiphertextBlob=ciphertext, GrantTokens=[grant_token]))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException decrypting with an Encrypt-only grant token, got {code!r}"
    )
    assert message == (
        f"User: {session_arn} is not authorized to perform: kms:Decrypt on resource: {key_arn} "
        f"because no identity-based policy allows the kms:Decrypt action"
    ), f"unexpected message: {message!r}"
    # effect absent: no plaintext was ever handed back for the rejected call above (exception raised)

    # positive control: a grant that DOES include Decrypt lets the same role decrypt the same ciphertext
    full_grant = kms.create_grant(KeyId=key_id, GranteePrincipal=role_arn, Operations=["Encrypt", "Decrypt"])
    full_token = full_grant["GrantToken"]
    ctx.on_cleanup(lambda: kms.retire_grant(GrantToken=full_token))
    decrypted2 = _retry_on_access_denied(
        lambda: role_kms.decrypt(CiphertextBlob=ciphertext, GrantTokens=[full_token])
    )["Plaintext"]
    assert decrypted2 == plaintext, (
        f"expected {plaintext!r} once the grant token also authorizes Decrypt, got {decrypted2!r}"
    )


_SESSION_NAME = "sim2real-session"


def _session_arn(role_arn: str, session_name: str) -> str:
    """The assumed-role session ARN STS issues for role_arn under session_name."""
    account, role_path = role_arn.split(":")[4], role_arn.split(":")[5]
    return f"arn:aws:sts::{account}:assumed-role/{role_path.split('/')[-1]}/{session_name}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
