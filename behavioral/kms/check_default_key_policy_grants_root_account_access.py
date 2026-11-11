"""default-key-policy-grants-root-account-access."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-key-policy-grants-root-account-access"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key created without a Policy gets a default whose first statement grants account root
    kms:*; a PutKeyPolicy that locks the caller out of kms:PutKeyPolicy raises
    MalformedPolicyDocumentException and leaves the policy untouched unless the check is bypassed.
    """
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    caller_arn = caller["Arn"]

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-defpolicy-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-default-key-policy-grants-root-account-access"}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # Access flows through the root statement plus the caller's IAM policy, which can take a few
    # seconds to take effect on a just-created key, so AccessDeniedException is retried.
    default_policy = json.loads(
        _retry_on_access_denied(
            lambda: kms.get_key_policy(KeyId=key_id, PolicyName="default")
        )["Policy"]
    )
    statements = default_policy["Statement"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    def _grants_root_full_access(stmt: dict) -> bool:
        if stmt.get("Effect") != "Allow":
            return False
        principal = stmt.get("Principal", {})
        principal_aws = principal.get("AWS") if isinstance(principal, dict) else None
        principal_aws_list = principal_aws if isinstance(principal_aws, list) else [principal_aws]
        if root_arn not in principal_aws_list:
            return False
        action = stmt.get("Action")
        action_list = action if isinstance(action, list) else [action]
        return "kms:*" in action_list

    root_stmt = next((s for s in statements if _grants_root_full_access(s)), None)
    assert root_stmt is not None, (
        f"default key policy has no root full-access statement for {root_arn}: {statements}"
    )

    # Break the lockout-safety guarantee: a replacement policy that grants the calling
    # principal enough to read the policy and clean the key up, but deliberately omits
    # any path to kms:PutKeyPolicy for it (dropping the root "Enable IAM User Permissions"
    # statement entirely) -- the safety check must reject this even though every OTHER
    # action still works for the caller.
    locked_out_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadAndCleanupOnly",
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": ["kms:GetKeyPolicy", "kms:DescribeKey", "kms:ScheduleKeyDeletion"],
                "Resource": "*",
            },
            {
                "Sid": "OnlyLogsService",
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
        ],
    }
    err = _retry_put_key_policy_expect_error(
        lambda: kms.put_key_policy(
            KeyId=key_id, PolicyName="default", Policy=json.dumps(locked_out_policy)
        )
    )
    assert err.get("Code") == "MalformedPolicyDocumentException", err
    assert err.get("Message") == (
        "The new key policy will not allow you to update the key policy in the future."
    ), err

    # Effect absent: the key's policy (still granting root) is unchanged by the rejected call.
    unchanged = json.loads(
        _retry_on_access_denied(lambda: kms.get_key_policy(KeyId=key_id, PolicyName="default"))[
            "Policy"
        ]
    )
    assert unchanged == default_policy, (
        f"a rejected PutKeyPolicy must leave the document unchanged: "
        f"expected {default_policy}, got {unchanged}"
    )

    # Positive control: the identical policy succeeds once the safety check is bypassed,
    # proving the rejection above was specifically the lockout-safety gate, not a blanket
    # rejection of any policy that omits the root statement. GetKeyPolicy still works
    # afterward because the replacement policy explicitly (deliberately) kept that one
    # action for the caller -- only kms:PutKeyPolicy access was actually lost.
    _retry_on_access_denied(
        lambda: kms.put_key_policy(
            KeyId=key_id,
            PolicyName="default",
            Policy=json.dumps(locked_out_policy),
            BypassPolicyLockoutSafetyCheck=True,
        )
    )
    updated = json.loads(
        _retry_on_access_denied(lambda: kms.get_key_policy(KeyId=key_id, PolicyName="default"))[
            "Policy"
        ]
    )
    assert updated == locked_out_policy, (
        f"bypassed PutKeyPolicy must store exactly the submitted document: "
        f"expected {locked_out_policy}, got {updated}"
    )
    assert updated != default_policy, (
        f"the stored policy must have actually changed from the default root-granting policy, "
        f"got {updated}"
    )

    # Confirm the lockout actually took effect: the caller that just replaced its own
    # policy can no longer call PutKeyPolicy on this key at all (not even to restore it).
    lockout = _error(
        lambda: kms.put_key_policy(
            KeyId=key_id, PolicyName="default", Policy=json.dumps(default_policy)
        )
    )
    assert lockout.get("Code") == "AccessDeniedException", lockout
    assert lockout.get("Message") == (
        f"User: {caller_arn} is not authorized to perform: kms:PutKeyPolicy on resource: "
        f"{key_arn} because no resource-based policy allows the kms:PutKeyPolicy action"
    ), lockout


def _error(fn):
    """The ClientError's Error dict. An unexpected success raises, so a target that accepts
    what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _retry_on_access_denied(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
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


def _retry_put_key_policy_expect_error(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Retry a PutKeyPolicy expected to fail past transient AccessDeniedException; return any
    other ClientError's Error dict. An unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                return exc.response["Error"]
            last_exc = exc
            time.sleep(interval_s)
            continue
        raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")
    raise AssertionError(f"call kept failing with AccessDeniedException: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
