"""associate-distribution-tenant-web-acl-not-found-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "associate-distribution-tenant-web-acl-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating a well-formed but nonexistent web ACL ARN with a tenant fails with
    InvalidArgument "The specified web ACL isn't valid. ..." and leaves the tenant's ETag and
    customizations unchanged; a real web ACL then associates as an override."""
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # The web ACL is created first so its cleanup runs after the tenant's and distribution's
    # (LIFO): WAF refuses to delete a web ACL that a CloudFront resource still references.
    web_acl_arn = _create_web_acl(ctx)
    dist_id = _create_multi_tenant_distribution(ctx)
    tenant_id, etag = _create_disabled_tenant(ctx, dist_id)

    bogus_arn = (
        f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/"
        f"{ctx.unique_name('sim2real-missing-')}/00000000-0000-0000-0000-000000000000"
    )
    code, msg = _error_code_and_message(
        lambda: cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=bogus_arn, IfMatch=etag)
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r} ({msg!r}) arn={bogus_arn!r}"
    invalid_acl_msg = (
        "The specified web ACL isn't valid. Specify a web ACL that was previously validated "
        "and try again."
    )
    assert msg == invalid_acl_msg, (
        f"expected the 'not previously validated' web ACL message, got {msg!r} -- a generic "
        "InvalidArgument here could just as well mean a malformed request"
    )

    # Effect absent: a failed association must not have advanced the tenant's version, and
    # must not have set a web ACL customization either.
    after = cf.get_distribution_tenant(Identifier=tenant_id)
    assert after["ETag"] == etag, "tenant version changed despite the association failing"
    assert not (after["DistributionTenant"].get("Customizations") or {}).get("WebAcl"), (
        "tenant gained a WebAcl customization despite the association failing"
    )

    # Positive control: a real web ACL associates successfully, and the terminal read is
    # independent -- through GetDistributionTenant, not the mutating call's own response.
    ok = cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=web_acl_arn, IfMatch=etag)
    assert ok["WebACLArn"] == web_acl_arn
    assert ok["ETag"] != etag

    got = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    web_acl = (got.get("Customizations") or {}).get("WebAcl") or {}
    assert web_acl.get("Arn") == web_acl_arn, (
        f"expected Customizations.WebAcl.Arn to be set to {web_acl_arn!r}, got {web_acl!r}"
    )
    assert web_acl.get("Action") == "override", f"expected Action 'override', got {web_acl.get('Action')!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _multi_tenant_origin_config() -> dict:
    return {
        "Id": "origin1",
        "DomainName": "www.example.com",
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real associate-distribution-tenant-web-acl-not-found-rejected",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [_multi_tenant_origin_config()]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id


def _create_disabled_tenant(ctx, dist_id: str):
    cf = ctx.client("cloudfront")
    # CloudFront denylists *.example.com/.example.org/.example.net outright with
    # InvalidArgument ("Domain Name not allowed") -- those roots are IANA-reserved
    # documentation domains. A random, unregistered .com name passes the same
    # format/denylist check without requiring us to actually own or DNS-validate it.
    domain = f"{ctx.unique_name('sim2real-cf-tenant-')}.com"
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        # Every distribution tenant needs at least one certificate. ValidationTokenHost
        # "self-hosted" defers domain-control validation to us (never performed here), so
        # CreateDistributionTenant -- the prerequisite under test -- succeeds without owning
        # `domain`; "cloudfront" instead demands CloudFront verify the domain immediately and
        # rejects with InvalidArgument ("Could not verify Domain Name ownership") in this setup.
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id, resp["ETag"]


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    import time

    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


def _create_web_acl(ctx) -> str:
    waf = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-cf-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        Rules=[],
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": name.replace("-", ""),
        },
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]
    arn = summary["ARN"]
    ctx.on_cleanup(lambda: _delete_web_acl(ctx, name, web_acl_id))
    return arn


def _delete_web_acl(ctx, name: str, web_acl_id: str) -> None:
    waf = ctx.client("wafv2")
    # WAF can keep reporting the association briefly after the tenant is deleted.
    deadline = time.monotonic() + 300
    while True:
        lock_token = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)["LockToken"]
        try:
            waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=lock_token)
            return
        except waf.exceptions.WAFAssociatedItemException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(15)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
