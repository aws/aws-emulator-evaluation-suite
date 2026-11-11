"""disassociate-unassociated-resource-leaves-subscription-unchanged."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-unassociated-resource-leaves-subscription-unchanged"
GROUP = "subscription-lifecycle"
SERVICES = ["cloudfront", "pricing-plan-manager", "wafv2"]

#: AWS managed cache policy "Managed-CachingDisabled": a fixed, AWS-published id, identical in
#: every account.
_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_SYNC_DEADLINE_S = 180.0
_SYNC_INTERVAL_S = 5.0
_DEPLOY_DEADLINE_S = 900.0
_DEPLOY_INTERVAL_S = 5.0
_WEB_ACL_LOCKED = (
    "You can't remove or replace the web ACL for your distribution. Distributions with a "
    "pricing plan subscription must have a web ACL resource."
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _ppm_client(ctx):
    """pricing-plan-manager serves only us-east-1, at an api.aws host botocore does not
    resolve by default; ctx.service_url names that host on real AWS and the target's endpoint
    otherwise."""
    return ctx.client(
        "pricing-plan-manager",
        region="us-east-1",
        endpoint_url=ctx.service_url("https://pricingplanmanager.us-east-1.api.aws"),
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _wait_deployed(ctx, cf, dist_id: str) -> str:
    """Poll GetDistribution to ``Deployed``; returns the ETag of the terminal read."""
    budget = _budget_s(ctx, _DEPLOY_DEADLINE_S)
    deadline = time.monotonic() + budget
    while True:
        resp = cf.get_distribution(Id=dist_id)
        status = resp["Distribution"]["Status"]
        if status == "Deployed":
            return resp["ETag"]
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("distribution deploy: the run budget ended first; not graded")
            raise AssertionError(f"distribution still {status!r} after {budget:.0f}s")
        time.sleep(_DEPLOY_INTERVAL_S)


def _set_web_acl(cf, dist_id: str, web_acl_arn: str, *, enabled: bool | None = None) -> None:
    """Read the distribution's current config and PUT it back with WebACLId set."""
    current = cf.get_distribution_config(Id=dist_id)
    cfg = current["DistributionConfig"]
    cfg["WebACLId"] = web_acl_arn
    if enabled is not None:
        cfg["Enabled"] = enabled
    cf.update_distribution(Id=dist_id, IfMatch=current["ETag"], DistributionConfig=cfg)


def _detach_when_unsubscribed(cf, dist_id: str) -> None:
    """Disable the distribution and drop its web ACL, retrying while a subscription that is
    being cancelled still holds the ACL in place."""
    deadline = time.monotonic() + _SYNC_DEADLINE_S
    while True:
        cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
        if not cfg["Enabled"] and not cfg.get("WebACLId"):
            return
        try:
            _set_web_acl(cf, dist_id, "", enabled=False)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidArgument" or err.get("Message") != _WEB_ACL_LOCKED:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(_SYNC_INTERVAL_S)


def _subscribable_distribution(ctx, cf, waf) -> tuple[str, str, str]:
    """A disabled distribution with its own CLOUDFRONT web ACL attached and deployed, both
    deleted at cleanup; returns (distribution id, distribution ARN, web ACL ARN)."""
    name = ctx.unique_name("sim2real-xsvc-ppm-dist-")
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": name,
        "Comment": name,
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "origin1",
            "DomainName": "www.example.com",
            "CustomOriginConfig": {
                "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            },
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _MANAGED_CACHING_DISABLED,
        },
    })["Distribution"]
    dist_id = dist["Id"]

    def _delete_distribution() -> None:
        _detach_when_unsubscribed(cf, dist_id)
        etag = _wait_deployed(ctx, cf, dist_id)
        cf.delete_distribution(Id=dist_id, IfMatch=etag)

    ctx.on_cleanup(_teardown(_delete_distribution, "NoSuchDistribution"))

    acl_name = ctx.unique_name("sim2real-xsvc-ppm-acl-")
    web_acl = waf.create_web_acl(
        Name=acl_name, Scope="CLOUDFRONT", DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False,
            "MetricName": "sim2realProbePpm",
        },
    )["Summary"]

    def _delete_web_acl() -> None:
        # WAF refuses to delete an ACL a distribution still references, so the distribution
        # goes first; WAF's association bookkeeping can lag that delete, so retry on it.
        try:
            _delete_distribution()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
        deadline = time.monotonic() + _SYNC_DEADLINE_S
        while True:
            current = waf.get_web_acl(Name=acl_name, Scope="CLOUDFRONT", Id=web_acl["Id"])
            try:
                waf.delete_web_acl(Name=acl_name, Scope="CLOUDFRONT", Id=web_acl["Id"],
                                   LockToken=current["LockToken"])
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "WAFAssociatedItemException":
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(_SYNC_INTERVAL_S)

    ctx.on_cleanup(_teardown(_delete_web_acl, "WAFNonexistentItemException"))

    _wait_deployed(ctx, cf, dist_id)
    _set_web_acl(cf, dist_id, web_acl["ARN"])
    _wait_deployed(ctx, cf, dist_id)
    return dist_id, dist["ARN"], web_acl["ARN"]


def _wait_active(ctx, ppm, arn: str) -> dict:
    """Poll GetSubscription until ACTIVE; returns the final response."""
    budget = _budget_s(ctx, _SYNC_DEADLINE_S)
    deadline = time.monotonic() + budget
    while True:
        resp = ppm.get_subscription(arn=arn)
        status = resp["subscription"]["status"]
        if status == "ACTIVE":
            return resp
        assert status != "FAILED", f"subscription reports FAILED: {resp['subscription']!r}"
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("subscription ACTIVE: the run budget ended first; not graded")
            raise AssertionError(f"subscription still {status!r} after {budget:.0f}s")
        time.sleep(_SYNC_INTERVAL_S)


def _cancel(ppm, arn: str) -> None:
    """Cancel the FREE subscription and wait until GetSubscription no longer finds it."""
    current = ppm.get_subscription(arn=arn)
    ppm.cancel_subscription(arn=arn, ifMatch=current["eTag"])
    deadline = time.monotonic() + _SYNC_DEADLINE_S
    while True:
        try:
            ppm.get_subscription(arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"subscription still present {_SYNC_DEADLINE_S}s after cancel")
        time.sleep(_SYNC_INTERVAL_S)


def _subscribe(ctx, ppm, dist_arn: str, web_acl_arn: str, **kwargs) -> dict:
    """A FREE flat-rate subscription for the distribution and web ACL, cancelled at cleanup;
    returns its ACTIVE GetSubscription response."""
    created = ppm.create_subscription(
        planFamily="CloudFront", planTier="FREE", resourceArns=[dist_arn, web_acl_arn], **kwargs,
    )
    arn = created["subscription"]["arn"]
    ctx.on_cleanup(_teardown(lambda: _cancel(ppm, arn), "ResourceNotFoundException"))
    return _wait_active(ctx, ppm, arn)


def _subscriptions_naming(ppm, resource_arn: str) -> list[str]:
    """ARNs of every subscription in the account, across all pages, that covers ``resource_arn``."""
    arns, kwargs = [], {}
    while True:
        page = ppm.list_subscriptions(**kwargs)
        arns += [
            s["arn"] for s in page.get("subscriptionSummaries", [])
            if resource_arn in (s.get("resourceArns") or [])
        ]
        if not page.get("nextToken"):
            return arns
        kwargs["nextToken"] = page["nextToken"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateResourcesFromSubscription naming a resource the subscription does not cover
    changes nothing: the resources, the status and the ETag read back as before.
    """
    cf = ctx.client("cloudfront")
    # A CLOUDFRONT-scope web ACL is managed only through the us-east-1 endpoint.
    waf = ctx.client("wafv2", region="us-east-1")
    ppm = _ppm_client(ctx)
    dist_id, dist_arn, web_acl_arn = _subscribable_distribution(ctx, cf, waf)
    active = _subscribe(ctx, ppm, dist_arn, web_acl_arn)
    sub_arn = active["subscription"]["arn"]
    outsider = f"arn:aws:route53:::hostedzone/Z{ctx.unique_name('SIM2REAL').upper()[:19]}"

    resp = ppm.disassociate_resources_from_subscription(
        arn=sub_arn, resourceArns=[outsider], ifMatch=active["eTag"],
    )
    assert sorted(resp["subscription"]["resourceArns"]) == sorted([dist_arn, web_acl_arn]), (
        f"the response lists resources {resp['subscription']['resourceArns']!r}"
    )
    after = ppm.get_subscription(arn=sub_arn)
    assert sorted(after["subscription"]["resourceArns"]) == sorted([dist_arn, web_acl_arn]), (
        f"a later read lists resources {after['subscription']['resourceArns']!r}"
    )
    assert after["subscription"]["status"] == "ACTIVE", f"status is {after['subscription']['status']!r}"
    assert after["eTag"] == active["eTag"], (
        f"a no-op disassociation moved the ETag from {active['eTag']!r} to {after['eTag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
