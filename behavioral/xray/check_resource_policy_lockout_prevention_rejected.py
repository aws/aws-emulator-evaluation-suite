"""resource-policy-lockout-prevention-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-lockout-prevention-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a self-locking document with LockoutPreventionException and does
    not persist it, while a scoped document succeeds; with BypassPolicyLockoutCheck=True the same
    lockout document is accepted and listed."""
    xray = ctx.client("xray")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]
    good_name = ctx.unique_name("sim2real-behav-xrpolicy-good-")
    policy_name = ctx.unique_name("sim2real-behav-xrpolicy-")

    good_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowScopedIngest",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "xray:PutTraceSegments",
                    "Resource": "*",
                }
            ],
        }
    )
    good_resp = xray.put_resource_policy(PolicyName=good_name, PolicyDocument=good_document)
    ctx.on_cleanup(lambda: xray.delete_resource_policy(PolicyName=good_name))
    assert good_resp["ResourcePolicy"]["PolicyName"] == good_name, (
        f"positive control: a non-self-locking policy must succeed without "
        f"BypassPolicyLockoutCheck, got {good_resp!r}"
    )

    lockout_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenySelfPutResourcePolicy",
                    "Effect": "Deny",
                    "Principal": {"AWS": caller_arn},
                    "Action": "xray:PutResourcePolicy",
                    "Resource": "*",
                }
            ],
        }
    )

    code, message = _error_code(
        lambda: xray.put_resource_policy(PolicyName=policy_name, PolicyDocument=lockout_document)
    )
    assert code == "LockoutPreventionException", (
        f"expected LockoutPreventionException for a self-locking policy document, got {code!r}"
    )
    expected_message = (
        "The new resource policy will not allow the caller of this request to call "
        "PutResourcePolicy in the future."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    existing_names = {
        p["PolicyName"] for p in xray.list_resource_policies().get("ResourcePolicies", [])
    }
    assert policy_name not in existing_names, (
        "a resource policy that failed the lockout-prevention check was nonetheless persisted"
    )
    assert good_name in existing_names, (
        f"positive control {good_name!r} unexpectedly disappeared: {existing_names!r}"
    )

    put_resp = xray.put_resource_policy(
        PolicyName=policy_name,
        PolicyDocument=lockout_document,
        BypassPolicyLockoutCheck=True,
    )
    ctx.on_cleanup(lambda: xray.delete_resource_policy(PolicyName=policy_name))
    assert put_resp["ResourcePolicy"]["PolicyName"] == policy_name, (
        f"expected bypassed put to return PolicyName={policy_name!r}, got {put_resp!r}"
    )

    existing_names_after = {
        p["PolicyName"] for p in xray.list_resource_policies().get("ResourcePolicies", [])
    }
    assert policy_name in existing_names_after, (
        f"expected {policy_name!r} to be present after BypassPolicyLockoutCheck=True, "
        f"got {existing_names_after!r}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
