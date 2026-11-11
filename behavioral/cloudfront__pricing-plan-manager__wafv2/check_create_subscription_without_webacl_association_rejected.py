"""create-subscription-without-webacl-association-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-subscription-without-webacl-association-rejected"
GROUP = "subscription-eligibility-rejected"
SERVICES = ["cloudfront", "pricing-plan-manager", "wafv2"]

#: AWS managed cache policy "Managed-CachingDisabled" — a fixed, AWS-published id, identical in
#: every account.
_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_SYNC_DEADLINE_S = 120.0
_SYNC_INTERVAL_S = 5.0
_DEPLOY_DEADLINE_S = 900.0
_DEPLOY_INTERVAL_S = 5.0


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


def _wait_deployed(cf, dist_id: str) -> str:
    """Poll GetDistribution to ``Deployed``; returns the ETag of the terminal read."""
    deadline = time.monotonic() + _DEPLOY_DEADLINE_S
    while True:
        resp = cf.get_distribution(Id=dist_id)
        status = resp["Distribution"]["Status"]
        if status == "Deployed":
            return resp["ETag"]
        if time.monotonic() > deadline:
            raise AssertionError(f"distribution {dist_id} still {status!r} after {_DEPLOY_DEADLINE_S}s")
        time.sleep(_DEPLOY_INTERVAL_S)


def _attach_web_acl(cf, dist_id: str, web_acl_arn: str) -> None:
    """Read the distribution's current config and PUT it back with WebACLId set."""
    current = cf.get_distribution_config(Id=dist_id)
    cfg = current["DistributionConfig"]
    cfg["WebACLId"] = web_acl_arn
    cf.update_distribution(Id=dist_id, IfMatch=current["ETag"], DistributionConfig=cfg)


def _disable_and_detach(cf, dist_id: str) -> None:
    """Read the distribution's current config and PUT it back disabled and without a web ACL."""
    current = cf.get_distribution_config(Id=dist_id)
    cfg = current["DistributionConfig"]
    if not cfg["Enabled"] and not cfg.get("WebACLId"):
        return
    cfg["Enabled"] = False
    cfg["WebACLId"] = ""
    cf.update_distribution(Id=dist_id, IfMatch=current["ETag"], DistributionConfig=cfg)


def _wait_subscription(ppm, arn: str, *, until) -> dict:
    """Poll GetSubscription until ``status`` is in ``until``; returns the final body."""
    deadline = time.monotonic() + _SYNC_DEADLINE_S
    while True:
        resp = ppm.get_subscription(arn=arn)
        status = resp["subscription"]["status"]
        if status in until:
            return resp
        assert status != "FAILED", f"subscription {arn} reports FAILED: {resp['subscription']!r}"
        if time.monotonic() > deadline:
            raise AssertionError(f"subscription {arn} still {status!r} after {_SYNC_DEADLINE_S}s")
        time.sleep(_SYNC_INTERVAL_S)


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSubscription rejects a CloudFront distribution that has no WAF web ACL associated
    with it yet, and the identical call succeeds once that association is in place.
    """
    cf = ctx.client("cloudfront")
    # A CLOUDFRONT-scope web ACL is managed only through the us-east-1 endpoint.
    waf = ctx.client("wafv2", region="us-east-1")
    ppm = _ppm_client(ctx)

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
    dist_arn = dist["ARN"]

    def _delete_distribution() -> None:
        _disable_and_detach(cf, dist_id)
        etag = _wait_deployed(cf, dist_id)
        cf.delete_distribution(Id=dist_id, IfMatch=etag)

    ctx.on_cleanup(_teardown(_delete_distribution, "NoSuchDistribution"))

    acl_name = ctx.unique_name("sim2real-xsvc-ppm-acl-")
    web_acl = waf.create_web_acl(
        Name=acl_name, Scope="CLOUDFRONT", DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False,
            "MetricName": "sim2realProbePpmRej",
        },
    )["Summary"]
    web_acl_arn = web_acl["ARN"]
    web_acl_id = web_acl["Id"]

    def _delete_web_acl() -> None:
        # The distribution still names this web ACL until it too is gone (WAF refuses to
        # delete an ACL a distribution references), so drop the distribution first; LIFO
        # would otherwise run this net before the distribution's own. WAF's own association
        # bookkeeping can lag a moment behind the distribution's deletion, so retry the
        # delete on that one documented condition.
        try:
            _delete_distribution()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
        deadline = time.monotonic() + _SYNC_DEADLINE_S
        while True:
            current = waf.get_web_acl(Name=acl_name, Scope="CLOUDFRONT", Id=web_acl_id)
            try:
                waf.delete_web_acl(
                    Name=acl_name, Scope="CLOUDFRONT", Id=web_acl_id,
                    LockToken=current["LockToken"],
                )
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "WAFAssociatedItemException":
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(_SYNC_INTERVAL_S)

    ctx.on_cleanup(_teardown(_delete_web_acl, "WAFNonexistentItemException"))

    _wait_deployed(cf, dist_id)

    # Negative: the distribution has no web ACL associated with it yet.
    code, message = _error(
        lambda: ppm.create_subscription(
            planFamily="CloudFront", planTier="FREE",
            resourceArns=[dist_arn, web_acl_arn], approvalMode="IMMEDIATE",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        f"The following resources are not eligible for this subscription tier: {dist_arn}."
    ), f"unexpected rejection message: {message!r}"
    # Effect-absent: the rejected call left no subscription covering this distribution.
    leftover = _subscriptions_naming(ppm, dist_arn)
    assert leftover == [], f"the rejected CreateSubscription left subscriptions naming {dist_arn}: {leftover!r}"

    # Positive control: the identical call succeeds once the web ACL is associated.
    _attach_web_acl(cf, dist_id, web_acl_arn)
    _wait_deployed(cf, dist_id)

    created = ppm.create_subscription(
        planFamily="CloudFront", planTier="FREE",
        resourceArns=[dist_arn, web_acl_arn], approvalMode="IMMEDIATE",
    )
    sub_arn = created["subscription"]["arn"]

    def _cancel_subscription() -> None:
        current = ppm.get_subscription(arn=sub_arn)
        ppm.cancel_subscription(arn=sub_arn, ifMatch=current["eTag"])
        deadline = time.monotonic() + _SYNC_DEADLINE_S
        while True:
            try:
                ppm.get_subscription(arn=sub_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"subscription {sub_arn} still present {_SYNC_DEADLINE_S}s after cancel")
            time.sleep(_SYNC_INTERVAL_S)

    ctx.on_cleanup(_teardown(_cancel_subscription, "ResourceNotFoundException"))

    active = _wait_subscription(ppm, sub_arn, until=("ACTIVE",))["subscription"]
    assert active["status"] == "ACTIVE", f"expected ACTIVE, got {active['status']!r}"
    assert set(active["resourceArns"]) == {dist_arn, web_acl_arn}, (
        f"expected the distribution and web ACL associated, got {active['resourceArns']!r}"
    )
    # Positive control for the effect-absent read: the same listing finds the accepted one.
    listed = _subscriptions_naming(ppm, dist_arn)
    assert listed == [sub_arn], f"expected ListSubscriptions to name only {sub_arn} for {dist_arn}, got {listed!r}"

    _cancel_subscription()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
