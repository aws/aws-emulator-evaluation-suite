"""grant-token-enables-immediate-use-before-propagation."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "grant-token-enables-immediate-use-before-propagation"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The GrantToken returned by CreateGrant permits immediate use of the granted operation,
    even though ListGrants visibility for the same grant is only eventually consistent.

    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/grant-tokens.html
    """
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    principal_arn = _principal_arn_for_policy(sts)

    # The policy omits the root "Enable IAM User Permissions" statement and never allows
    # kms:Encrypt, so the immediate Encrypt success is attributable to the GrantToken.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GrantAdminOnlyNoEncrypt",
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": [
                    "kms:CreateGrant",
                    "kms:ListGrants",
                    "kms:RevokeGrant",
                    "kms:DescribeKey",
                    "kms:ScheduleKeyDeletion",
                    "kms:GetKeyPolicy",
                    "kms:PutKeyPolicy",
                ],
                "Resource": "*",
            }
        ],
    }

    key_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-granttoken-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-granttoken-immediate-use"}],
    )["KeyMetadata"]
    key_id, key_arn = key_meta["KeyId"], key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Without a grant, the principal has no path to Encrypt under the policy above.
    baseline_code, baseline_message = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"no-grant-yet"))
    assert baseline_code == "AccessDeniedException", baseline_code
    caller_arn = sts.get_caller_identity()["Arn"]
    assert baseline_message == (
        f"User: {caller_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        f"because no resource-based policy allows the kms:Encrypt action"
    ), f"unexpected message: {baseline_message!r}"

    grant = kms.create_grant(
        KeyId=key_id,
        GranteePrincipal=principal_arn,
        Operations=["Encrypt"],
    )
    grant_id = grant["GrantId"]
    grant_token = grant["GrantToken"]
    ctx.on_cleanup(lambda: kms.revoke_grant(KeyId=key_id, GrantId=grant_id))

    # Immediate use, right after CreateGrant returns, using only the GrantToken -- no sleep.
    result = kms.encrypt(
        KeyId=key_id,
        Plaintext=b"encrypted-immediately-via-grant-token",
        GrantTokens=[grant_token],
    )
    assert result["CiphertextBlob"]

    # The grant must eventually become visible via ListGrants (eventually consistent).
    found = _poll_until_grant(ctx, key_id, grant_id, timeout_s=90.0)
    assert found is not None, f"grant {grant_id} never became visible via ListGrants"
    assert found["GranteePrincipal"] == principal_arn
    assert "Encrypt" in found["Operations"]


def _principal_arn_for_policy(sts) -> str:
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


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until_grant(ctx, key_id: str, grant_id: str, timeout_s: float = 90.0) -> dict[str, Any] | None:
    kms = ctx.client("kms")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kms.list_grants(KeyId=key_id)
        for g in resp.get("Grants", []):
            if g["GrantId"] == grant_id:
                return g
        time.sleep(3.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
