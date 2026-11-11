"""put-resource-policy-lockout-prevented."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-resource-policy-lockout-prevented"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy accepts a scoped and a wildcard-Principal Allow policy, refuses a
    deny-everyone xray:* policy with LockoutPreventionException and its documented message
    without creating it, and accepts it with BypassPolicyLockoutCheck."""
    xray = ctx.client("xray")

    good_name = ctx.unique_name("sim2real-xray-rp-good-")
    good_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ScopedAccess",
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": ["xray:PutTraceSegments"],
                "Resource": "*",
            }
        ],
    }
    xray.put_resource_policy(PolicyName=good_name, PolicyDocument=json.dumps(good_document))
    ctx.on_cleanup(lambda: xray.delete_resource_policy(PolicyName=good_name))

    # The claim this check exists to make: a bare wildcard Principal on its own is not
    # the thing X-Ray rejects. Assert it directly instead of only asserting it in prose --
    # an Allow statement naming Principal="*" with no Deny/lockout shape must be accepted.
    wildcard_name = ctx.unique_name("sim2real-xray-rp-wildcard-")
    wildcard_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WildcardPrincipalAllow",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["xray:PutTraceSegments"],
                "Resource": "*",
            }
        ],
    }
    xray.put_resource_policy(PolicyName=wildcard_name, PolicyDocument=json.dumps(wildcard_document))
    ctx.on_cleanup(lambda: xray.delete_resource_policy(PolicyName=wildcard_name))
    assert wildcard_name in _list_all_policy_names(ctx), (
        f"expected a bare wildcard-Principal Allow policy {wildcard_name!r} to be accepted "
        f"(X-Ray does not reject wildcard principals by themselves)"
    )

    bad_name = ctx.unique_name("sim2real-xray-rp-lockout-")
    bad_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyEveryoneEverything",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "xray:*",
                "Resource": "*",
            }
        ],
    }
    code, message = _error(
        lambda: xray.put_resource_policy(PolicyName=bad_name, PolicyDocument=json.dumps(bad_document))
    )
    assert code == "LockoutPreventionException", (
        f"expected LockoutPreventionException for a policy that denies everyone "
        f"(including the caller) all xray actions, got {code!r}"
    )
    assert message == (
        "The new resource policy will not allow the caller of this request to call "
        "PutResourcePolicy in the future."
    ), f"unexpected message: {message!r}"

    # Effect must be absent: the rejected policy was never created.
    all_names = _list_all_policy_names(ctx)
    assert bad_name not in all_names, f"rejected policy {bad_name!r} was created anyway"

    # Positive control: the properly scoped policy from setup is present and intact.
    assert good_name in all_names, f"expected control policy {good_name!r} to exist"

    # BypassPolicyLockoutCheck=True explicitly opts out of the safety check -- the
    # same lockout-shaped document must now be accepted (and is cleaned up).
    xray.put_resource_policy(
        PolicyName=bad_name,
        PolicyDocument=json.dumps(bad_document),
        BypassPolicyLockoutCheck=True,
    )
    ctx.on_cleanup(lambda: xray.delete_resource_policy(PolicyName=bad_name))
    all_names_after_bypass = _list_all_policy_names(ctx)
    assert bad_name in all_names_after_bypass, (
        f"expected {bad_name!r} to be created once BypassPolicyLockoutCheck=True was set"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _list_all_policy_names(ctx):
    xray = ctx.client("xray")
    names = []
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        page = xray.list_resource_policies(**kwargs)
        names.extend(p["PolicyName"] for p in page.get("ResourcePolicies", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

