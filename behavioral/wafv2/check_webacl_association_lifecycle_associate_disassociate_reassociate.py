"""webacl-association-lifecycle-associate-disassociate-reassociate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-association-lifecycle-associate-disassociate-reassociate"
GROUP = "state-machine"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource cycles cleanly through associate -> disassociate ->
    reassociate to a DIFFERENT WebACL, fully exercising the association
    state machine; GetWebACLForResource reflects each state exactly."""
    wafv2 = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")
    scope = "REGIONAL"

    def _visibility(metric):
        return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}

    def _create_web_acl(tag):
        wname = ctx.unique_name(f"sim2real-behav-webacl-{tag}-")
        summary = wafv2.create_web_acl(
            Name=wname,
            Scope=scope,
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility(wname),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )["Summary"]
        ctx.on_cleanup(_web_acl_deleter(wafv2, wname, scope, summary["Id"]))
        return summary

    web_acl_1 = _create_web_acl("a")
    web_acl_2 = _create_web_acl("b")

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real:managed": "true"}
    )["UserPool"]
    pool_arn = pool["Arn"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    ctx.on_cleanup(lambda: _safe_disassociate(wafv2, pool_arn))

    _associate_with_retry(wafv2, web_acl_1["ARN"], pool_arn)
    observed_1 = _poll_until(
        lambda: wafv2.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL"),
        lambda w: w is not None,
    )
    assert observed_1["ARN"] == web_acl_1["ARN"], (
        f"expected GetWebACLForResource to reflect {web_acl_1['ARN']!r} after AssociateWebACL, "
        f"observed {observed_1['ARN']!r}"
    )

    wafv2.disassociate_web_acl(ResourceArn=pool_arn)
    _poll_until(
        lambda: wafv2.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL"),
        lambda w: w is None,
    )

    _associate_with_retry(wafv2, web_acl_2["ARN"], pool_arn)
    observed_2 = _poll_until(
        lambda: wafv2.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL"),
        lambda w: w is not None,
    )
    assert observed_2["ARN"] == web_acl_2["ARN"], (
        f"expected GetWebACLForResource to reflect the reassociated {web_acl_2['ARN']!r}, "
        f"observed {observed_2['ARN']!r}"
    )
    assert observed_2["ARN"] != web_acl_1["ARN"], (
        f"expected reassociation to move off the original {web_acl_1['ARN']!r}, "
        f"but GetWebACLForResource still reflects it"
    )


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
