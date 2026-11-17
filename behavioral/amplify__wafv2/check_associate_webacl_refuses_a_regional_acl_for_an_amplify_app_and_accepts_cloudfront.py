"""associate-webacl-refuses-a-regional-acl-for-an-amplify-app-and-accepts-cloudfront."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-webacl-refuses-a-regional-acl-for-an-amplify-app-and-accepts-cloudfront"
GROUP = "overly-permissive"
SERVICES = ["amplify", "wafv2"]

# WAFv2 manages CLOUDFRONT-scope web ACLs only through the us-east-1 endpoint.
_CLOUDFRONT_REGION = "us-east-1"
_REGIONAL_REJECTED = (
    "WAFInvalidParameterException",
    "The resource is not supported in current region",
)
_WAF_SETTLE_DEADLINE_S = 360.0


def _visibility(metric: str) -> dict:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": metric}


def _error_code_and_message(fn):
    """The (Error.Code, Error.Message) ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_for_waf_status(amplify, app_id: str, wanted: frozenset,
                          deadline_s: float = _WAF_SETTLE_DEADLINE_S, interval_s: float = 10.0):
    """Poll GetApp's wafConfiguration.wafStatus until it reaches a terminal value in ``wanted``."""
    deadline = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < deadline:
        cfg = amplify.get_app(appId=app_id)["app"].get("wafConfiguration") or {}
        last = cfg.get("wafStatus")
        if last in wanted:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"wafConfiguration.wafStatus never reached {sorted(wanted)}, last observed {last!r}")


def _web_acl_deleter(waf, name, scope, web_acl_id):
    def _delete():
        try:
            current = waf.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
                return
            raise
        try:
            waf.delete_web_acl(Name=name, Scope=scope, Id=web_acl_id, LockToken=current["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    return _delete


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateWebACL accepts a CLOUDFRONT-scope web ACL for an Amplify app, and
    GetWebACLForResource then reports it; the same call with a REGIONAL-scope web ACL
    and a second Amplify app is refused.

    Reference: https://docs.aws.amazon.com/amplify/latest/userguide/amplify-waf-configuration.html
    """
    amplify = ctx.client("amplify")
    waf_global = ctx.client("wafv2", region=_CLOUDFRONT_REGION)
    waf_regional = ctx.client("wafv2")

    app_cf = amplify.create_app(name=ctx.unique_name("sim2real-behav-amp-cf-"))["app"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_cf["appId"]))

    app_reg = amplify.create_app(name=ctx.unique_name("sim2real-behav-amp-reg-"))["app"]
    ctx.on_cleanup(lambda: amplify.delete_app(appId=app_reg["appId"]))

    cf_name = ctx.unique_name("sim2real-behav-webacl-cf-")
    cf_acl = waf_global.create_web_acl(
        Name=cf_name, Scope="CLOUDFRONT", DefaultAction={"Allow": {}}, Rules=[],
        VisibilityConfig=_visibility(cf_name.replace("-", "")),
    )["Summary"]
    ctx.on_cleanup(_web_acl_deleter(waf_global, cf_name, "CLOUDFRONT", cf_acl["Id"]))

    reg_name = ctx.unique_name("sim2real-behav-webacl-reg-")
    reg_acl = waf_regional.create_web_acl(
        Name=reg_name, Scope="REGIONAL", DefaultAction={"Allow": {}}, Rules=[],
        VisibilityConfig=_visibility(reg_name.replace("-", "")),
    )["Summary"]
    ctx.on_cleanup(_web_acl_deleter(waf_regional, reg_name, "REGIONAL", reg_acl["Id"]))

    waf_global.associate_web_acl(WebACLArn=cf_acl["ARN"], ResourceArn=app_cf["appArn"])

    def _disassociate_cf():
        # Amplify processes (dis)association asynchronously; wait for the prior association
        # to settle before the disassociate, which AWS otherwise refuses as still in progress.
        _wait_for_waf_status(amplify, app_cf["appId"], frozenset({"ASSOCIATION_SUCCESS", "ASSOCIATION_FAILED"}))
        waf_global.disassociate_web_acl(ResourceArn=app_cf["appArn"])

    ctx.on_cleanup(_disassociate_cf)

    status = _wait_for_waf_status(
        amplify, app_cf["appId"], frozenset({"ASSOCIATION_SUCCESS", "ASSOCIATION_FAILED"})
    )
    assert status == "ASSOCIATION_SUCCESS", (
        f"associating the CLOUDFRONT web ACL with the Amplify app reached status {status!r}"
    )

    reflected = amplify.get_app(appId=app_cf["appId"])["app"]["wafConfiguration"]
    assert reflected["webAclArn"] == cf_acl["ARN"], (
        f"the app's wafConfiguration names {reflected['webAclArn']!r}, expected {cf_acl['ARN']!r}"
    )

    observed = waf_global.get_web_acl_for_resource(ResourceArn=app_cf["appArn"]).get("WebACL")
    assert observed is not None, "GetWebACLForResource reports no web ACL for the associated app"
    assert observed["ARN"] == cf_acl["ARN"], (
        f"GetWebACLForResource reflects {observed['ARN']!r}, expected the associated {cf_acl['ARN']!r}"
    )

    code, message = _error_code_and_message(
        lambda: waf_regional.associate_web_acl(WebACLArn=reg_acl["ARN"], ResourceArn=app_reg["appArn"])
    )
    assert (code, message) == _REGIONAL_REJECTED, (code, message)

    still_unassociated = waf_global.get_web_acl_for_resource(ResourceArn=app_reg["appArn"]).get("WebACL")
    assert still_unassociated is None, (
        f"the refused REGIONAL association still left {still_unassociated!r} on the second app"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
