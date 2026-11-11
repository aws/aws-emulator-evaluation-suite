"""grant-constraint-mismatched-context-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "grant-constraint-mismatched-context-rejected"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A grant token with an EncryptionContextSubset constraint lets a permission-less role Encrypt
    with the required context, but Encrypt with a mismatched or missing context is denied
    with AccessDeniedException."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-grantctxneg-"),
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
    ctx.on_cleanup(lambda: _safe_revoke_grant(kms, key_id, grant.get("GrantId")))

    assumed_kms = _assumed_role_client(ctx, role_arn, "kms")

    control = assumed_kms.encrypt(
        KeyId=key_arn,
        Plaintext=b"sim2real-control-plaintext",
        EncryptionContext=required_context,
        GrantTokens=[grant_token],
    )
    assert control["CiphertextBlob"], "positive control must produce ciphertext"

    denied = (
        f"User: {_session_arn(role_arn, _SESSION_NAME)} is not authorized to perform: kms:Encrypt "
        f"on resource: {key_arn} because no identity-based policy allows the kms:Encrypt action"
    )

    code, message = _error(
        lambda: assumed_kms.encrypt(
            KeyId=key_arn,
            Plaintext=b"sim2real-mismatched-context-plaintext",
            EncryptionContext={"Department": "Engineering"},
            GrantTokens=[grant_token],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == denied, f"unexpected message: {message!r}"

    code_missing, message_missing = _error(
        lambda: assumed_kms.encrypt(
            KeyId=key_arn,
            Plaintext=b"sim2real-missing-context-plaintext",
            GrantTokens=[grant_token],
        )
    )
    assert code_missing == "AccessDeniedException", (
        f"expected AccessDeniedException, got {code_missing!r}"
    )
    assert message_missing == denied, f"unexpected message: {message_missing!r}"


_SESSION_NAME = "sim2real-kms-grant-neg-check"


def _session_arn(role_arn: str, session_name: str) -> str:
    account, role_path = role_arn.split(":")[4], role_arn.split(":")[5]
    return f"arn:aws:sts::{account}:assumed-role/{role_path.split('/')[-1]}/{session_name}"




def _create_bare_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kmsgrantneg-role-")
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
    sts = ctx.client("sts")
    deadline = time.monotonic() + 30.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )
            break
        except Exception as err:
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


def _error(fn: Any) -> tuple[str, str | None]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
