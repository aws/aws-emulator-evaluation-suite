"""tenant-config-on-direct-distribution-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-config-on-direct-distribution-rejected"
GROUP = "multi-tenant-distribution"
SERVICES = ["cloudfront"]

#: CloudFront's control plane is global and answers only in us-east-1.
CLOUDFRONT_REGION = "us-east-1"
#: Ceiling for a distribution reaching Deployed; a bound to fail at, not a latency claim.
_DEPLOYED_DEADLINE_S = 900
#: The managed CachingOptimized cache policy.
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A distribution with no ConnectionMode, and one with ConnectionMode direct, each refuse a
    TenantConfig block with InvalidArgument; the same block is accepted on a tenant-only one.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    tok = ctx.unique_name("sim2real-cfmt-tc-").lower()
    oac_id = _create_oac(ctx, cf, tok)
    host = _origin_host(tok, ctx.region)
    tenant_config = {
        "ParameterDefinitions": [{
            "Name": "TenantPath",
            "Definition": {"StringSchema": {"Comment": "a per-tenant discriminator",
                                            "Required": True}},
        }]
    }
    expected = "The parameter TenantConfig cannot be set for a direct distribution."

    no_mode = _config(f"{tok}-nomode", host, oac_id, connection_mode=None,
                      tenant_config=tenant_config)
    no_mode["Comment"] = f"{tok} nomode"
    code, message = _error(lambda: cf.create_distribution(DistributionConfig=no_mode))
    assert code == "InvalidArgument", (
        f"TenantConfig with no ConnectionMode was refused with {code!r}, expected 'InvalidArgument'"
    )
    assert message == expected, f"the no-ConnectionMode refusal says {message!r}, expected {expected!r}"

    direct = _config(f"{tok}-direct", host, oac_id, connection_mode="direct",
                     tenant_config=tenant_config)
    direct["Comment"] = f"{tok} direct"
    code, message = _error(lambda: cf.create_distribution(DistributionConfig=direct))
    assert code == "InvalidArgument", (
        f"TenantConfig with ConnectionMode direct was refused with {code!r}, expected 'InvalidArgument'"
    )
    assert message == expected, f"the direct refusal says {message!r}, expected {expected!r}"

    control = _config(f"{tok}-control", host, oac_id, connection_mode="tenant-only",
                      tenant_config=tenant_config)
    control["Comment"] = f"{tok} control"
    dist = _create_distribution(ctx, cf, control)
    assert dist["DistributionConfig"].get("ConnectionMode") == "tenant-only", (
        f"the control distribution reports ConnectionMode "
        f"{dist['DistributionConfig'].get('ConnectionMode')!r}, expected 'tenant-only'"
    )
    stored = cf.get_distribution_config(Id=dist["Id"])["DistributionConfig"]
    stored_names = [p["Name"] for p in stored["TenantConfig"]["ParameterDefinitions"]]
    assert stored_names == ["TenantPath"], (
        f"a later read of the control distribution's TenantConfig shows {stored_names!r}, "
        f"expected ['TenantPath']"
    )

    # Effect absent: neither refused config left a distribution in either partition.
    for comment in (no_mode["Comment"], direct["Comment"]):
        assert _modes_holding(cf, comment) == [], (
            f"a refused create left a distribution commented {comment!r}"
        )
    assert _modes_holding(cf, control["Comment"]) == ["tenant-only"], (
        "the control distribution is not listed in exactly the tenant-only partition"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last: {last!r})")


def _error(fn) -> tuple[str, str]:
    """Return the AWS error (code, message) fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call succeeded; real AWS rejects it, so there is no error code")


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
    """Disable if enabled, wait for Deployed, delete; a failure raises."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise RuntimeError(f"distribution {dist_id}: {exc}") from exc
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
                raise RuntimeError(f"origin access control {oac_id}: {exc}") from exc

    ctx.on_cleanup(_delete)
    return oac_id


def _config(caller_ref: str, origin_host: str, oac_id: str, *, connection_mode, tenant_config) -> dict:
    """A distribution config with one fixed-path S3 origin, varying only ConnectionMode/TenantConfig."""
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real multi-tenant tenant services",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "S3Origin",
            "DomainName": origin_host,
            "OriginPath": "/fixed",
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
    }
    if connection_mode is not None:
        config["ConnectionMode"] = connection_mode
    if tenant_config is not None:
        config["TenantConfig"] = tenant_config
    return config


def _create_distribution(ctx, cf, config: dict) -> dict:
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
