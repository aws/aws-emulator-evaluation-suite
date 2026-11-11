"""delete-webacl-blocked-while-associated-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-webacl-blocked-while-associated-rejected"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWebACL on a WebACL that is currently associated with a resource is
    rejected with WAFAssociatedItemException; the WebACL is not deleted. Once
    disassociated, deletion succeeds (positive control, same WebACL)."""
    wafv2 = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")
    scope = "REGIONAL"

    web_acl_name = ctx.unique_name("sim2real-behav-webacl-")
    created = wafv2.create_web_acl(
        Name=web_acl_name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": web_acl_name,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    web_acl_id = created["Id"]
    web_acl_arn = created["ARN"]

    ctx.on_cleanup(_web_acl_deleter(wafv2, web_acl_name, scope, web_acl_id))

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real-check": CHECK}
    )["UserPool"]
    pool_arn = pool["Arn"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    ctx.on_cleanup(lambda: _safe_disassociate(wafv2, pool_arn))

    _associate_with_retry(wafv2, web_acl_arn, pool_arn)
    _poll_until(
        lambda: wafv2.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL"),
        lambda w: w is not None and w.get("ARN") == web_acl_arn,
    )

    current = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
    lock_token = current["LockToken"]

    code, message = _error(
        lambda: wafv2.delete_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id, LockToken=lock_token)
    )
    assert code == "WAFAssociatedItemException", f"expected WAFAssociatedItemException, got {code}"
    assert message == (
        "AWS WAF couldn’t perform the operation because your resource is being used by "
        "another resource or it’s associated with another resource."
    ), message

    # effect absent: the web ACL still exists
    still_there = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
    assert still_there["WebACL"]["Id"] == web_acl_id, (
        f"WebACL {web_acl_id} vanished after a rejected DeleteWebACL"
    )

    # break the association, then deletion (positive control) must succeed
    wafv2.disassociate_web_acl(ResourceArn=pool_arn)
    _poll_until(
        lambda: wafv2.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL"),
        lambda w: w is None,
    )

    final = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
    wafv2.delete_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id, LockToken=final["LockToken"])

    code_after_delete, message_after_delete = _error(
        lambda: wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
    )
    assert code_after_delete == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException after delete, got {code_after_delete!r}"
    )
    assert message_after_delete == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message_after_delete


def _error(fn):
    """Return (code, message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _web_acl_deleter(wafv2, name, scope, web_acl_id):
    def _delete():
        try:
            current = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "WAFNonexistentItemException":
                return
            raise
        try:
            wafv2.delete_web_acl(Name=name, Scope=scope, Id=web_acl_id, LockToken=current["LockToken"])
        except ClientError as e:
            if e.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    return _delete


def _safe_disassociate(wafv2, resource_arn):
    try:
        wafv2.disassociate_web_acl(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _associate_with_retry(wafv2, web_acl_arn, resource_arn, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            wafv2.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=resource_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "WAFUnavailableEntityException":
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
