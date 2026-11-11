"""disassociate-webacl-removes-association-visible-in-getwebaclforresource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-webacl-removes-association-visible-in-getwebaclforresource"
GROUP = "state-machine"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DisassociateWebACL, GetWebACLForResource for that resource stops
    returning a WebACL, confirming the association was actually torn down
    server-side (not just accepted and ignored)."""
    wafv2 = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")

    web_acl_name = ctx.unique_name("sim2real-behav-wacl-")
    summary = wafv2.create_web_acl(
        Name=web_acl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": web_acl_name,
        },
        Tags=[{"Key": "Team", "Value": "sim2real"}],
    )["Summary"]
    web_acl_arn = summary["ARN"]
    web_acl_id = summary["Id"]
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: wafv2.delete_web_acl(
                Name=web_acl_name,
                Scope="REGIONAL",
                Id=web_acl_id,
                LockToken=wafv2.get_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=web_acl_id)["LockToken"],
            )
        )
    )

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"Team": "sim2real"}
    )["UserPool"]
    pool_arn = pool["Arn"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: cognito.delete_user_pool(UserPoolId=pool_id)))
    ctx.on_cleanup(lambda: _safe_call(lambda: wafv2.disassociate_web_acl(ResourceArn=pool_arn)))

    _associate_with_retry(wafv2, web_acl_arn, pool_arn)

    observed = _wait_for_association(wafv2, pool_arn)
    assert observed["ARN"] == web_acl_arn, (
        f"expected GetWebACLForResource to report WebACL ARN {web_acl_arn!r}, "
        f"got {observed['ARN']!r}"
    )

    wafv2.disassociate_web_acl(ResourceArn=pool_arn)

    _wait_for_disassociation(wafv2, pool_arn)


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "WAFNonexistentItemException",
        ):
            raise


def _associate_with_retry(wafv2, web_acl_arn, resource_arn, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            wafv2.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=resource_arn)
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "WAFUnavailableEntityException":
                raise
            time.sleep(3)
    raise AssertionError(f"AssociateWebACL never succeeded: {last_err}")


def _wait_for_association(wafv2, resource_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = wafv2.get_web_acl_for_resource(ResourceArn=resource_arn).get("WebACL")
        if last is not None:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"GetWebACLForResource never reflected the AssociateWebACL; last WebACL={last!r}"
    )


def _wait_for_disassociation(wafv2, resource_arn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = "unchecked"
    while time.monotonic() < deadline:
        last = wafv2.get_web_acl_for_resource(ResourceArn=resource_arn).get("WebACL")
        if last is None:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"GetWebACLForResource still returned a WebACL after DisassociateWebACL; last WebACL={last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
