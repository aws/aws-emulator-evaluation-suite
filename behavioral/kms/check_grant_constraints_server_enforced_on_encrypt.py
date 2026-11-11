"""grant-constraints-server-enforced-on-encrypt."""
from __future__ import annotations

import json
import time
from typing import Any, Callable


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "grant-constraints-server-enforced-on-encrypt"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no KMS permissions can Encrypt via a grant token when it supplies the grant's
    required EncryptionContextSubset, and the owner decrypts the result back to the plaintext."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-grantctx-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))

    role_arn = _create_bare_role(ctx)
    required_context = {"Department": "Finance"}

    grant = _create_grant_with_retry(
        kms,
        key_id=key_id,
        role_arn=role_arn,
        operations=["Encrypt"],
        constraints={"EncryptionContextSubset": required_context},
    )
    grant_token = grant["GrantToken"]
    ctx.on_cleanup(
        lambda: _safe_revoke_grant(kms, key_id, grant.get("GrantId"))
    )

    assumed_kms = _assumed_role_client(ctx, role_arn, "kms")

    ciphertext = assumed_kms.encrypt(
        KeyId=key_arn,
        Plaintext=b"sim2real-grant-constrained-plaintext",
        EncryptionContext=required_context,
        GrantTokens=[grant_token],
    )["CiphertextBlob"]

    plaintext = kms.decrypt(
        CiphertextBlob=ciphertext, KeyId=key_id, EncryptionContext=required_context
    )["Plaintext"]
    expected = b"sim2real-grant-constrained-plaintext"
    assert plaintext == expected, f"expected {expected!r} from owner decrypt, got {plaintext!r}"



def _create_bare_role(ctx: Any) -> str:
    """Create a role trusted by the calling account with no policies, so a grant is its only KMS
    permission."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kmsgrant-role-")
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
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = created["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _assumed_role_client(ctx: Any, role_arn: str, service: str) -> Any:
    """Assume role_arn, retrying while IAM propagates; build a client from only its credentials."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 30.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(
                RoleArn=role_arn, RoleSessionName="sim2real-kms-grant-check"
            )
            break
        except Exception as err:  # role not yet assumable everywhere
            last_err = err
            time.sleep(2.0)
    else:
        raise AssertionError(f"could not assume role {role_arn}: {last_err}")
    creds = resp["Credentials"]
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _create_grant_with_retry(
    kms: Any,
    *,
    key_id: str,
    role_arn: str,
    operations: list[str],
    constraints: dict[str, Any],
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Retry CreateGrant while a just-created role is not yet visible to KMS (IAM is eventually
    consistent)."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kms.create_grant(
                KeyId=key_id,
                GranteePrincipal=role_arn,
                Operations=operations,
                Constraints=constraints,
            )
        except Exception as err:  # InvalidArnException while IAM role propagates
            last_err = err
            time.sleep(2.0)
    raise AssertionError(f"create_grant never succeeded for {role_arn}: {last_err}")


def _safe_delete_role(iam: Any, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_revoke_grant(kms: Any, key_id: str, grant_id: str | None) -> None:
    if not grant_id:
        return
    try:
        kms.revoke_grant(KeyId=key_id, GrantId=grant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(
    probe: Callable[[], Any], *, timeout_s: float, interval_s: float = 1.0
) -> Any | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result:
            return result
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
