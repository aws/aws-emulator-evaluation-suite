"""distribution-tenant-required-default-parameter-schema-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-tenant-required-default-parameter-schema-rejected"
GROUP = "multi-tenant-distribution"
SERVICES = ["cloudfront"]

#: CloudFront's control plane is global and answers only in us-east-1.
CLOUDFRONT_REGION = "us-east-1"
#: The longest wait any step takes (a distribution reaching Deployed); a ceiling to fail at,
#: never a latency claim.
_DEPLOYED_DEADLINE_S = 900
#: The managed CachingOptimized cache policy the estate's distribution uses.
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
#: CloudFront's tenant-parameter syntax: each tenant's TenantPath value is substituted at the edge.
TENANT_ORIGIN_PATH = "/{{TenantPath}}"

_INVALID_SCHEMA = (
    "InvalidArgument",
    "One or more parameter definition schemas aren't valid. Review the parameters for the "
    "multi-tenant distribution and try again.",
)


@tags("axis:rejection", "concern:negative-classes", "concern:representation", "plane:control",
      "cap:c1")
def run(ctx) -> None:
    """A tenant parameter definition that is both Required and carries a DefaultValue is refused
    at CreateDistribution; dropping either half of that combination succeeds.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    tok = ctx.unique_name("sim2real-cfmt-rd-").lower()
    oac_id = _create_oac(ctx, cf, tok)
    host = _origin_host(tok, ctx.region)

    # THE NEGATIVE: a StringSchema that is Required AND declares a DefaultValue.
    both = _tenant_only_config(f"{tok}-both", host, oac_id, required=True,
                               default_value="root-tenant")
    _expect_error(lambda: cf.create_distribution(DistributionConfig=both), *_INVALID_SCHEMA)
    assert _modes_holding(cf, both["Comment"]) == [], (
        "the refused create left a distribution behind"
    )

    # POSITIVE CONTROL 1: Required, with no DefaultValue at all.
    required_only = _tenant_only_config(f"{tok}-reqonly", host, oac_id, required=True,
                                        default_value=None)
    dist_a = _create_distribution(ctx, cf, required_only)
    schema_a = dist_a["DistributionConfig"]["TenantConfig"]["ParameterDefinitions"][0][
        "Definition"]["StringSchema"]
    assert schema_a["Required"] is True, f"control A lost Required: {schema_a!r}"
    assert "DefaultValue" not in schema_a, f"control A unexpectedly carries DefaultValue: {schema_a!r}"

    # POSITIVE CONTROL 2: a DefaultValue, with Required False.
    default_only = _tenant_only_config(f"{tok}-defonly", host, oac_id, required=False,
                                       default_value="root-tenant")
    dist_b = _create_distribution(ctx, cf, default_only)
    schema_b = dist_b["DistributionConfig"]["TenantConfig"]["ParameterDefinitions"][0][
        "Definition"]["StringSchema"]
    assert schema_b["Required"] is False, f"control B lost Required False: {schema_b!r}"
    assert schema_b["DefaultValue"] == "root-tenant", f"control B lost DefaultValue: {schema_b!r}"


def _expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message); raises itself when the call SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected code {code!r}, got {err['Code']!r} ({err.get('Message')!r})"
        assert err["Message"] == message, f"expected message {message!r}, got {err['Message']!r}"
        return
    raise AssertionError(
        f"expected ({code!r}, {message!r}); the call succeeded instead: {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result) holds; return it, or fail naming the last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id: str) -> str:
    """Poll GetDistribution to Status=Deployed and return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=_DEPLOYED_DEADLINE_S, interval_s=10.0,
                description=f"distribution {dist_id} reaching Deployed")
    return holder["etag"]


def _retire_distribution(cf, dist_id: str) -> None:
    """Disable if enabled, wait for Deployed, delete. A failed delete raises.

    The id is server-minted, so the distribution is deleted by id.
    """
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_oac(ctx, cf, name: str) -> str:
    """An S3 origin access control that signs every request with SigV4, with its cleanup."""
    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": name,
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]

    def _delete() -> None:
        try:
            cf.delete_origin_access_control(
                Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
                raise

    ctx.on_cleanup(_delete)
    return oac_id


def _tenant_only_config(caller_ref: str, origin_host: str, oac_id: str, *, required: bool,
                        default_value: str | None) -> dict:
    """A tenant-only distribution with one string TenantConfig parameter used in the origin path."""
    schema: dict = {"Comment": "S3 keyspace prefix for this tenant", "Required": required}
    if default_value is not None:
        schema["DefaultValue"] = default_value
    return {
        "CallerReference": caller_ref,
        "Comment": caller_ref,
        "Enabled": False,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "S3Origin",
            "DomainName": origin_host,
            "OriginPath": TENANT_ORIGIN_PATH,
            "OriginAccessControlId": oac_id,
            "S3OriginConfig": {"OriginAccessIdentity": ""},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "S3Origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "CachePolicyId": CACHING_OPTIMIZED,
            "Compress": True,
        },
        "HttpVersion": "http2",
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True,
                              "MinimumProtocolVersion": "TLSv1.2_2021"},
        "TenantConfig": {"ParameterDefinitions": [{
            "Name": "TenantPath",
            "Definition": {"StringSchema": schema},
        }]},
    }


def _create_distribution(ctx, cf, config: dict) -> dict:
    """CreateDistribution with its retirement registered on the very next statement."""
    dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist["Id"]))
    return dist


def _origin_host(name: str, region: str) -> str:
    """An S3 REST origin host. CloudFront never resolves it on the control plane."""
    return f"{name}.s3.{region}.amazonaws.com"


def _modes_holding(cf, comment: str) -> list[str]:
    """Which connection-mode partitions hold a distribution carrying this run's unique comment."""
    found: list[str] = []
    for mode in ("tenant-only", "direct"):
        kwargs = {"ConnectionMode": mode}
        while True:
            page = cf.list_distributions_by_connection_mode(**kwargs)["DistributionList"]
            found += [mode for d in page.get("Items") or [] if d.get("Comment") == comment]
            if not page.get("IsTruncated"):
                break
            kwargs["Marker"] = page["NextMarker"]
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
