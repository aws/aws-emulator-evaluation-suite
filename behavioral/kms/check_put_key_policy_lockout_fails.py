"""put-key-policy-lockout-fails."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-key-policy-lockout-fails"
GROUP = 'key_policy'
SERVICES = ['kms']


def _account_root_arn(key_arn: str) -> str:
    """Derive the account-root principal ARN from a KMS key ARN.

    The account id is the 5th ``:``-delimited field of
    ``arn:aws:kms:<region>:<account>:key/<id>``.
    """
    return f"arn:aws:iam::{key_arn.split(':')[4]}:root"


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a PutKeyPolicy on the key succeeds, a policy that would lock the caller out fails with
    MalformedPolicyDocumentException and the exact message, and GetKeyPolicy still returns the previous policy."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-policylockout-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    root = _account_root_arn(meta["Arn"])

    # Positive control: a policy that keeps root's kms:* admin access is accepted and stored
    # verbatim. Without this, "rejects the lockout document below" is indistinguishable from
    # "rejects every PutKeyPolicy on this key".
    admin_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": root},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(admin_policy))
    stored_admin = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert stored_admin == admin_policy, (
        f"a policy that retains root's kms:* admin access must be accepted and stored verbatim: "
        f"got {stored_admin!r}"
    )

    # The principal below is real (so the document itself is valid), but it is
    # granted only DescribeKey — nobody retains kms:PutKeyPolicy, so the key
    # would become unmanageable. KMS's lockout safety check must reject this.
    lockout_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OnlyDescribeNoAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": root},
                "Action": "kms:DescribeKey",
                "Resource": "*",
            }
        ],
    }
    code, message = _error(
        lambda: kms.put_key_policy(
            KeyId=key_id,
            PolicyName="default",
            Policy=json.dumps(lockout_policy),
            BypassPolicyLockoutSafetyCheck=False,
        )
    )
    assert code == "MalformedPolicyDocumentException", f"expected MalformedPolicyDocumentException, got {code}"
    assert message == "The new key policy will not allow you to update the key policy in the future.", (
        message
    )

    # Effect absent: an independent read (GetKeyPolicy, not the failed PutKeyPolicy call's own
    # response) proves the rejected lockout document did not overwrite the admin policy from the
    # positive control above.
    after = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    assert after == admin_policy, (
        f"a rejected lockout PutKeyPolicy must leave the prior policy unchanged: got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
