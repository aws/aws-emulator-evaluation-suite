"""edge-requests-deliver-requests-metric-with-global-dimension."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import requests

from behavioral_harness import tags

CHECK = "edge-requests-deliver-requests-metric-with-global-dimension"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

#: Marks a failure of the target's edge to serve as a data-plane failure, not an environment one.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled — every viewer request must reach the origin and be counted as its own
#: request, so nothing under test can be absorbed by an edge cache hit.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: How many edge requests to drive. Small, because the assertion is >= this number, not == it.
_REQUESTS = 5

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    900 s is roughly five times the observed create-to-Deployed and disable-to-Deployed time.
    """
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete.

    DeleteDistribution issued immediately after the disabling UpdateDistribution is refused with
    DistributionNotDisabled, so the second Deployed wait is mandatory rather than defensive.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _create_bucket(ctx, s3, bucket) -> None:
    # us-east-1 is the one region whose create_bucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAG_SET})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _allow_cloudfront_oac(s3, bucket, dist_arn) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))


def _fetch_ok(session, url, *, timeout_s=180.0, interval_s=5.0):
    """GET url until it answers 200, then return that response.

    Raises with DATAPLANE_MARKER on exhaustion: the distribution is Deployed, so not serving the
    object is a data-plane failure.
    """
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=15)
        except requests.RequestException as exc:  # transport only, during edge propagation
            last = exc
            return None
        return last

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


def _sum_of(cw, metric, dimensions, start, end) -> float:
    """Total Sum across every datapoint CloudWatch returns for this exact dimension set."""
    resp = cw.get_metric_statistics(
        Namespace="AWS/CloudFront", MetricName=metric, Dimensions=dimensions,
        StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
    )
    return sum(float(d["Sum"]) for d in resp["Datapoints"])


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/programming-cloudwatch-metrics.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Edge requests land in AWS/CloudFront Requests under exactly {DistributionId, Region=Global}
    (Sum >= requests issued; other dimension sets match nothing), and CacheHitRate appears only
    after a monitoring subscription enables additional metrics.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/programming-cloudwatch-metrics.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    # CloudFront is a global resource and publishes every distribution metric to CloudWatch in
    # us-east-1 only, whatever region served the viewer request.
    cw = ctx.client("cloudwatch", region="us-east-1")

    bucket = ctx.unique_name("sim2real-behav-cfmetric-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    key = "metric-probe.txt"
    body = b"sim2real-cloudfront-metric-probe"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfmetric-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfmetric-cr-"),
        "Comment": "sim2real cloudwatch metric delivery",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted and cannot be found by name.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    _allow_cloudfront_oac(s3, bucket, dist["ARN"])

    # Additional metrics (CacheHitRate among them) are opt-in per distribution. Enabling BEFORE any
    # traffic is what makes the CacheHitRate leg below attributable to the subscription.
    cf.create_monitoring_subscription(DistributionId=dist_id, MonitoringSubscription={
        "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"},
    })
    ctx.on_cleanup(lambda: cf.delete_monitoring_subscription(DistributionId=dist_id))
    read_back = cf.get_monitoring_subscription(DistributionId=dist_id)["MonitoringSubscription"]
    status = read_back["RealtimeMetricsSubscriptionConfig"]["RealtimeMetricsSubscriptionStatus"]
    assert status == "Enabled", (
        f"expected the monitoring subscription read back as Enabled, got {status!r}"
    )

    _wait_distribution_deployed(cf, dist_id)

    # One keep-alive session so every request lands on the same edge POP; the metric is aggregated
    # across POPs anyway, but a single connection keeps the request count unambiguous.
    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)
    url = f"{edge}/{key}"

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    first = _fetch_ok(session, url)
    assert first.content == body, (
        f"the edge served the wrong bytes before any metric was read: expected {body!r}, "
        f"got {first.content[:120]!r}"
    )
    issued = 1
    for _ in range(_REQUESTS - 1):
        r = session.get(url, timeout=15)
        assert r.status_code == 200, (
            f"a request that must be counted was refused: expected 200, got {r.status_code} / "
            f"{r.text[:200]!r}"
        )
        assert r.content == body, (
            f"expected the origin object {body!r}, got {r.content[:120]!r}"
        )
        issued += 1

    global_dims = [{"Name": "DistributionId", "Value": dist_id},
                   {"Name": "Region", "Value": "Global"}]

    def requests_sum() -> float:
        # EndTime is recomputed every poll so the window always covers the newest closed minute.
        return _sum_of(cw, "Requests", global_dims, window_start,
                       datetime.now(timezone.utc) + timedelta(minutes=1))

    # Bounded retry, not a sleep: CloudFront aggregates per minute and publishes with a lag, and
    # this is the propagation this check exists to bound. It raises on exhaustion.
    total = _poll_until(
        requests_sum, lambda s: s >= issued, timeout_s=900.0, interval_s=30.0,
        description=(f"AWS/CloudFront Requests Sum >= {issued} for distribution {dist_id} "
                     f"under DistributionId+Region=Global"),
    )
    assert total >= issued, (
        f"expected AWS/CloudFront Requests Sum >= {issued} (the requests this run issued), "
        f"got {total}"
    )

    # Twin controls in the SAME instant, on the same wiring that just proved delivery: CloudFront's
    # Region dimension is the literal 'Global', so neither of these dimension sets can match.
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    regional = _sum_of(cw, "Requests",
                       [{"Name": "DistributionId", "Value": dist_id},
                        {"Name": "Region", "Value": ctx.region}], window_start, end)
    assert regional == 0.0, (
        f"AWS/CloudFront Requests was published under Region={ctx.region!r}: expected 0 datapoints "
        f"summing to 0, got {regional} — the Region dimension must be the literal 'Global'"
    )
    partial = _sum_of(cw, "Requests", [{"Name": "DistributionId", "Value": dist_id}],
                      window_start, end)
    assert partial == 0.0, (
        f"a query naming DistributionId alone returned {partial}: expected 0, because CloudWatch "
        f"matches dimension SETS exactly and CloudFront always publishes DistributionId+Region"
    )

    # The dimension NAME set, read through a different operation than the datapoint query.
    listed = cw.list_metrics(Namespace="AWS/CloudFront", MetricName="Requests",
                             Dimensions=[{"Name": "DistributionId", "Value": dist_id}])["Metrics"]
    assert len(listed) == 1, (
        f"expected exactly one AWS/CloudFront Requests metric for {dist_id}, got {len(listed)}: "
        f"{listed!r}"
    )
    dim_names = sorted(d["Name"] for d in listed[0]["Dimensions"])
    assert dim_names == ["DistributionId", "Region"], (
        f"expected the dimension names ['DistributionId', 'Region'], got {dim_names}"
    )
    region_value = [d["Value"] for d in listed[0]["Dimensions"] if d["Name"] == "Region"]
    assert region_value == ["Global"], (
        f"expected the Region dimension value ['Global'], got {region_value}"
    )

    # CacheHitRate is an ADDITIONAL metric: it exists for this distribution only because this check
    # enabled the monitoring subscription above.
    def cache_hit_rate_metrics():
        return cw.list_metrics(
            Namespace="AWS/CloudFront", MetricName="CacheHitRate",
            Dimensions=[{"Name": "DistributionId", "Value": dist_id}],
        )["Metrics"]

    extra = _poll_until(
        cache_hit_rate_metrics, lambda m: len(m) == 1, timeout_s=900.0, interval_s=30.0,
        description=(f"AWS/CloudFront CacheHitRate to appear for {dist_id} because additional "
                     f"metrics are enabled"),
    )
    extra_dims = sorted(d["Name"] for d in extra[0]["Dimensions"])
    assert extra_dims == ["DistributionId", "Region"], (
        f"expected CacheHitRate to carry ['DistributionId', 'Region'], got {extra_dims}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
