"""origin-path-more-than-two-parameters-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "origin-path-more-than-two-parameters-rejected"
GROUP = "multi-tenant-distribution"
SERVICES = ["cloudfront"]

#: CloudFront's control plane is global and answers only in us-east-1.
CLOUDFRONT_REGION = "us-east-1"
#: The longest wait any step takes (a distribution reaching Deployed); a ceiling to fail at,
#: never a latency claim.
_DEPLOYED_DEADLINE_S = 900
#: The managed CachingOptimized cache policy.
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A multi-tenant distribution whose S3 origin OriginPath references three TenantConfig
    parameters is refused with InvalidArgument and creates nothing; the same origin referencing
    two of those parameters is accepted and its OriginPath round-trips unchanged."""
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    tok = ctx.unique_name("sim2real-cfmt-pc-").lower()
    oac_id = _create_oac(ctx, cf, tok)
    host = _origin_host(tok, ctx.region)

    three = _tenant_only_config(
        f"{tok}-three", host, oac_id, "/{{a}}/{{b}}/{{c}}", ["a", "b", "c"]
    )
    three["Comment"] = f"{tok} three"
    _REFUSAL = (
        "InvalidArgument",
        "Your request exceeds the maximum number of parameters per field. Specify fewer "
        "parameters and try again.",
    )
    code, message = _expect_error(
        lambda: cf.create_distribution(DistributionConfig=three),
        "CreateDistribution with a three-parameter OriginPath",
    )
    assert (code, message) == _REFUSAL, (
        f"the three-parameter refusal reads {(code, message)!r}, expected {_REFUSAL!r}"
    )
    assert _ids_commented(cf, three["Comment"]) == [], (
        "the refused three-parameter create left a distribution behind"
    )

    two = _tenant_only_config(
        f"{tok}-two", host, oac_id, "/{{a}}/{{b}}", ["a", "b"]
    )
    two["Comment"] = f"{tok} two"
    dist = _create_distribution(ctx, cf, two)
    origin_path = dist["DistributionConfig"]["Origins"]["Items"][0]["OriginPath"]
    assert origin_path == "/{{a}}/{{b}}", (
        f"the two-parameter origin round-trips OriginPath {origin_path!r}, expected '/{{a}}/{{b}}'"
    )
    assert _ids_commented(cf, two["Comment"]) == [dist["Id"]], (
        f"ListDistributions does not list exactly the accepted distribution {dist['Id']!r}"
    )

    # Re-assert the refusal is deterministic: the exact same request fails identically again.
    code2, message2 = _expect_error(
        lambda: cf.create_distribution(DistributionConfig=three),
        "repeating CreateDistribution with the three-parameter OriginPath",
    )
    assert (code2, message2) == _REFUSAL, (
        f"the repeated refusal reads {(code2, message2)!r}, expected {_REFUSAL!r}"
    )
    assert _ids_commented(cf, three["Comment"]) == [], (
        "the repeated refused create left a distribution behind"
    )


def _expect_error(fn, description):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises,
    because accepting a call AWS refuses must not read as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {description} to raise, but it succeeded with {result!r}")


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
    """Disable if enabled, wait for Deployed, delete; a failed delete raises."""
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


def _tenant_only_config(
    caller_ref: str, origin_host: str, oac_id: str, origin_path: str, param_names: list[str]
) -> dict:
    """A tenant-only distribution config with one S3 origin whose OriginPath references
    ``param_names``, each declared as a required string TenantConfig parameter."""
    return {
        "CallerReference": caller_ref,
        "Comment": "sim2real multi-tenant tenant services",
        "Enabled": False,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "S3Origin",
            "DomainName": origin_host,
            "OriginPath": origin_path,
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
        "TenantConfig": {"ParameterDefinitions": [
            {
                "Name": name,
                "Definition": {"StringSchema": {"Comment": f"path segment {name}",
                                                "Required": True}},
            }
            for name in param_names
        ]},
    }


def _create_distribution(ctx, cf, config: dict) -> dict:
    """CreateDistribution with its retirement registered on the very next statement."""
    dist = cf.create_distribution(DistributionConfig=config)["Distribution"]
    ctx.on_cleanup(lambda: _retire_distribution(cf, dist["Id"]))
    return dist


def _origin_host(name: str, region: str) -> str:
    """An S3 REST origin host. CloudFront never resolves it on the control plane."""
    return f"{name}.s3.{region}.amazonaws.com"


def _ids_commented(cf, comment: str) -> list[str]:
    """Ids ListDistributions returns whose Comment is exactly ``comment``."""
    found: list[str] = []
    kwargs: dict = {}
    while True:
        page = cf.list_distributions(**kwargs)["DistributionList"]
        found += [d["Id"] for d in page.get("Items") or [] if d.get("Comment") == comment]
        if not page.get("IsTruncated"):
            return found
        kwargs["Marker"] = page["NextMarker"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
