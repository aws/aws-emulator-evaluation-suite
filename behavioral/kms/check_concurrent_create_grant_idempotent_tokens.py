"""concurrent-create-grant-idempotent-tokens."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-grant-idempotent-tokens"
GROUP = "concurrency"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two structurally identical concurrent CreateGrant calls yield two independently valid grants."""
    kms = ctx.client("kms")
    key_id = _create_symmetric_key(ctx)
    role_arn = _create_zero_permission_role(ctx)
    creds = _assume_role_creds(ctx, role_arn)
    role_kms = _client_with_creds(ctx, "kms", creds)

    def make_grant():
        # deliberately no Name parameter -- CreateGrant dedup/idempotency is only engaged
        # when a Name is supplied, so two unnamed identical requests must each create a
        # genuinely new, independently-usable grant.
        return kms.create_grant(KeyId=key_id, GranteePrincipal=role_arn, Operations=["Encrypt"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(make_grant) for _ in range(2)]
        results = [f.result(timeout=30) for f in futures]

    grant_ids = {r["GrantId"] for r in results}
    assert len(grant_ids) == 2, f"expected 2 distinct grant ids from concurrent CreateGrant, got {grant_ids}"

    def own_grant_ids() -> set[str]:
        grants = kms.list_grants(KeyId=key_id)["Grants"]
        return {g["GrantId"] for g in grants if g["GranteePrincipal"] == role_arn}

    seen = _poll_until(own_grant_ids, lambda ids: grant_ids <= ids, timeout_s=60.0)
    assert grant_ids <= seen, f"ListGrants never showed both concurrently created grants: {seen}"

    for result in results:
        gid = result["GrantId"]
        ctx.on_cleanup(lambda gid=gid: kms.revoke_grant(KeyId=key_id, GrantId=gid))

    # each grant token must independently authorize Encrypt for the zero-permission role
    for result in results:
        token = result["GrantToken"]
        ciphertext = _retry_on_access_denied(
            lambda tok=token: role_kms.encrypt(
                KeyId=key_id, Plaintext=b"concurrent-grant-payload", GrantTokens=[tok]
            )
        )["CiphertextBlob"]
        plaintext = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
        assert plaintext == b"concurrent-grant-payload", (
            f"decrypted plaintext did not round-trip for grant {result['GrantId']}: got {plaintext!r}"
        )


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
                RoleArn=role_arn, RoleSessionName="sim2real-session", DurationSeconds=900
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
