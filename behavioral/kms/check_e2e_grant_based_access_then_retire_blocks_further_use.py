"""e2e-grant-based-access-then-retire-blocks-further-use."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-grant-based-access-then-retire-blocks-further-use"
GROUP = "e2e"
SERVICES = ["kms"]
SESSION_NAME = "sim2real-kms-grant-retire-check"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A policy-less role can Encrypt only via a grant; after RetireGrant its Encrypt fails
    AccessDeniedException, a fresh grant restores access, and the account can still Encrypt."""
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-grantretire-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: _safe_schedule_delete(kms, key_id))

    role_arn = _create_bare_role(ctx)

    grant = _create_grant_with_retry(kms, key_id=key_id, role_arn=role_arn, operations=["Encrypt"])
    grant_id = grant["GrantId"]
    grant_token = grant["GrantToken"]

    assumed_kms = _assumed_role_client(ctx, role_arn, "kms")

    plaintext = b"sim2real-grant-authorized-plaintext"
    ciphertext = assumed_kms.encrypt(
        KeyId=key_id, Plaintext=plaintext, GrantTokens=[grant_token]
    )["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext, KeyId=key_id)["Plaintext"]
    assert decrypted == plaintext, f"grant-authorized encrypt did not round-trip: {decrypted!r} != {plaintext!r}"

    # The creating account can always retire its grant; RetireGrant by GrantId needs the key ARN.
    kms.retire_grant(KeyId=key_arn, GrantId=grant_id)

    # A retired grant's token can keep authorizing for minutes until all endpoints update, so
    # probe without the token to evaluate the role's current authorization.
    code, message = _poll_until_refused(
        lambda: assumed_kms.encrypt(KeyId=key_id, Plaintext=plaintext),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert code == "AccessDeniedException", f"unexpected denial code: {code!r}"
    session_arn = (
        role_arn.replace(":iam::", ":sts::", 1).replace(":role/", ":assumed-role/", 1)
        + f"/{SESSION_NAME}"
    )
    expected_message = (
        f"User: {session_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        "because no identity-based policy allows the kms:Encrypt action"
    )
    assert message == expected_message, f"unexpected denial message: {message!r}"

    # Restore: a fresh grant re-authorizes, so the denial was about the retired grant.
    grant2 = _create_grant_with_retry(kms, key_id=key_id, role_arn=role_arn, operations=["Encrypt"])
    ctx.on_cleanup(lambda: _safe_retire_grant(kms, key_arn, grant2["GrantId"]))
    restored_ciphertext = assumed_kms.encrypt(
        KeyId=key_id, Plaintext=plaintext, GrantTokens=[grant2["GrantToken"]]
    )["CiphertextBlob"]
    restored_plain = kms.decrypt(CiphertextBlob=restored_ciphertext, KeyId=key_id)["Plaintext"]
    assert restored_plain == plaintext, (
        f"fresh grant on the same role did not restore encrypt: {restored_plain!r} != {plaintext!r}"
    )

    # Positive control: the key itself is unaffected.
    control_ciphertext = kms.encrypt(KeyId=key_id, Plaintext=b"sim2real-control-plaintext")[
        "CiphertextBlob"
    ]
    control_plain = kms.decrypt(CiphertextBlob=control_ciphertext, KeyId=key_id)["Plaintext"]
    assert control_plain == b"sim2real-control-plaintext", (
        f"account-direct encrypt broke after grant retirement: {control_plain!r}"
    )


def _create_bare_role(ctx: Any) -> str:
    """Create a role trusted by the calling account with no policies; return its ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kmsgrantretire-role-")
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
    """Assume role_arn (retrying past IAM propagation) and build a client with only its creds."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 20.0
    last_err: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=SESSION_NAME
            )
            break
        except Exception as err:  # role not yet assumable everywhere
            last_err = err
            time.sleep(2.0)
    if resp is None:
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
    timeout_s: float = 20.0,
) -> dict[str, Any]:
    """CreateGrant, retried while a just-created role is not yet visible to KMS (IAM is
    eventually consistent)."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kms.create_grant(
                KeyId=key_id, GranteePrincipal=role_arn, Operations=operations
            )
        except Exception as err:  # InvalidArnException while IAM role propagates
            last_err = err
            time.sleep(2.0)
    raise AssertionError(f"create_grant never succeeded for {role_arn}: {last_err}")


def _poll_until_refused(
    call: Callable[[], Any], *, timeout_s: float, interval_s: float = 1.0
) -> tuple[str, str]:
    """Repeat call() until it raises ClientError and return (Code, Message); a call that keeps
    succeeding past timeout_s raises."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            call()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call still succeeded {timeout_s}s after RetireGrant")


def _safe_delete_role(iam: Any, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_schedule_delete(client: Any, key_id: str) -> None:
    try:
        client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_retire_grant(client: Any, key_arn: str, grant_id: str) -> None:
    try:
        client.retire_grant(KeyId=key_arn, GrantId=grant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
