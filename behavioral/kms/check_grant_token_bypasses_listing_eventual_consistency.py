"""grant-token-bypasses-listing-eventual-consistency."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "grant-token-bypasses-listing-eventual-consistency"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Encrypt is denied without a grant, succeeds immediately with a fresh GrantToken, and the
    grant eventually appears in ListGrants: the token bypasses grant eventual consistency.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/grant-tokens.html
    """
    kms = ctx.client("kms")
    principal_arn = _principal_arn_for_policy(ctx)

    # The policy omits the root "Enable IAM User Permissions" statement and never allows
    # kms:Encrypt, so IAM policies cannot grant Encrypt: only the grant token can.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGrantAdminOnlyNoEncrypt",
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": [
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                    "kms:ListGrants",
                    "kms:RevokeGrant",
                    "kms:ScheduleKeyDeletion",
                    "kms:GetKeyPolicy",
                    "kms:PutKeyPolicy",
                ],
                "Resource": "*",
            }
        ],
    }

    key_meta = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Description=ctx.unique_name("sim2real-kms-grant-bypass-"),
        Policy=json.dumps(policy),
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Without a grant, the principal has no Encrypt permission under the policy above.
    baseline_code, baseline_message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"no-grant-yet"))
    assert baseline_code == "AccessDeniedException", (
        f"expected AccessDeniedException with no grant under the no-root-delegation policy, "
        f"got {baseline_code!r}"
    )
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    assert baseline_message == (
        f"User: {caller_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        f"because no resource-based policy allows the kms:Encrypt action"
    ), f"unexpected message: {baseline_message!r}"

    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=principal_arn,
        Operations=["Encrypt"],
    )
    grant_token = grant["GrantToken"]
    grant_id = grant["GrantId"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    # No sleep here: the GrantToken must work right now, not after propagation.
    encrypt_resp = kms.encrypt(
        KeyId=key_id, Plaintext=b"grant-token-bypass", GrantTokens=[grant_token]
    )
    assert encrypt_resp["CiphertextBlob"], (
        "expected Encrypt with a fresh GrantToken to return ciphertext immediately, "
        "with no propagation wait, but got an empty CiphertextBlob"
    )

    # The grant must eventually show up in ListGrants; only immediate visibility is not
    # guaranteed.
    def _grant_visible() -> bool:
        for page in kms.get_paginator("list_grants").paginate(KeyId=key_id):
            if any(g["GrantId"] == grant_id for g in page.get("Grants", [])):
                return True
        return False

    found = _poll_until(_grant_visible, lambda v: v, timeout_s=30, interval_s=2)
    if not found:
        raise AssertionError(
            f"grant {grant_id} never became visible via ListGrants within the poll window"
        )


def _principal_arn_for_policy(ctx) -> str:
    sts = ctx.client("sts")
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        # arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/SESSION_NAME
        #   -> arn:aws:iam::ACCOUNT:role/ROLE_NAME  (KMS key policies authorize the
        #   underlying IAM role, not the STS session ARN)
        parts = arn.split(":")
        account = parts[4]
        role_name = parts[5].split("/")[1]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
