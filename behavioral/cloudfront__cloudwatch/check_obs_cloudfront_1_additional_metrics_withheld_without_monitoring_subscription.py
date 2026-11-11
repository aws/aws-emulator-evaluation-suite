"""obs-cloudfront-1-additional-metrics-withheld-without-monitoring-subscription."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cloudfront-1-additional-metrics-withheld-without-monitoring-subscription"
GROUP = "metric-emission"
SERVICES = ["cloudfront", "cloudwatch"]

#: Marks a failure where the endpoint serves no edge at all, so it reads as a fidelity failure
#: rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: AWS managed cache policy "Managed-CachingOptimized". A fixed AWS-published id, identical in
#: every account. BOTH distributions use it, so the monitoring subscription is the ONLY difference.
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: Request counts this check issues to EACH distribution (identical traffic on both sides).
_PRESENT_REPEATS = 3
_ABSENT_REQUESTS = 2

_HTTP_TIMEOUT_S = 15.0
_METRIC_DEADLINE_S = 900.0
_METRIC_INTERVAL_S = 30.0
_REQUESTS_SLACK = 1.0
_RATE_TOLERANCE = 0.1

#: The additional (subscription-gated) metrics whose ABSENCE on the control is the claim.
_GATED = ("CacheHitRate", "OriginLatency", "403ErrorRate")

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

_MAX_ROUNDS = 10   # at most one measured round per minute, inside the 900 s metric deadline


def _round_key(i: int) -> str:
    """A present key used by exactly ONE measured round, so that round's first request misses."""
    return f"present-{i}.txt"

_WARMUP_KEY = "warmup.txt"
_ABSENT_KEY = "absent-never-written.txt"   # never written: the origin must refuse it
_PRESENT_BODY = b"sim2real-cloudfront-observability-present"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() + interval_s > deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distributions(cf, dist_ids) -> None:
    """Disable EVERY distribution first, then wait and delete each — cost is the max, not the sum.
    Ids deleted (or already gone) leave ``dist_ids``; the rest are leaks and are raised together."""
    failures: list[tuple[str, Exception]] = []
    for dist_id in list(dist_ids):
        try:
            cfg_resp = cf.get_distribution_config(Id=dist_id)
            cfg = cfg_resp["DistributionConfig"]
            if cfg.get("Enabled"):
                cfg["Enabled"] = False
                cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchDistribution":
                dist_ids.remove(dist_id)
                continue
            failures.append((f"cloudfront distribution {dist_id}: disable failed: {exc!r}", exc))
        except Exception as exc:  # noqa: BLE001 — collected so every distribution is still tried
            failures.append((f"cloudfront distribution {dist_id}: disable failed: {exc!r}", exc))
    for dist_id in list(dist_ids):
        try:
            etag = _wait_distribution_deployed(cf, dist_id)
            cf.delete_distribution(Id=dist_id, IfMatch=etag)
            dist_ids.remove(dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchDistribution":
                dist_ids.remove(dist_id)
                continue
            failures.append((f"cloudfront distribution {dist_id}: delete failed: {exc!r}", exc))
        except Exception as exc:  # noqa: BLE001
            failures.append((f"cloudfront distribution {dist_id}: delete failed: {exc!r}", exc))
    if failures:
        raise RuntimeError("; ".join(m for m, _ in failures)) from failures[-1][1]


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
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _allow_cloudfront_oac(s3, bucket, dist_arns) -> None:
    """Grant s3:GetObject ONLY — no s3:ListBucket — to exactly these distributions.
    Without ListBucket, S3 answers a signed GET for a missing key with 403 AccessDenied, not 404."""
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipalGetOnly",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": list(dist_arns)}},
        }],
    }))


def _distribution_config(ctx, bucket, oac_id, comment):
    return {
        "CallerReference": ctx.unique_name("sim2real-xsvc-cfobs-cr-"),
        "Comment": comment,
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
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    }


def _fetch_ok(session, url, *, timeout_s=300.0, interval_s=5.0):
    """GET url until it answers 200 (edge propagation after Deployed), then return it."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=_HTTP_TIMEOUT_S)
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


def _wait_for_fresh_minute(after: datetime) -> datetime:
    """Wait until the wall clock is in a LATER minute than `after`, at second 5..30 of it, so the
    burst lands in ONE CloudWatch 60 s period with no warm-up traffic. The 5 s lead absorbs
    clock skew; the 30 s tail leaves the burst room to finish."""
    floor = after.replace(second=0, microsecond=0)
    deadline = time.monotonic() + 150.0
    while time.monotonic() < deadline:
        now = datetime.now(timezone.utc)
        if now.replace(second=0, microsecond=0) > floor and 5 <= now.second <= 30:
            return now.replace(second=0, microsecond=0)
        time.sleep(0.5)
    raise AssertionError(f"host clock never reached a fresh minute after {after.isoformat()}")


def _minute_datapoints(cw, metric, dims, minute, *, statistic=None, extended=None):
    """Datapoints for exactly one 60 s period starting at `minute`."""
    kwargs = {"Namespace": "AWS/CloudFront", "MetricName": metric, "Dimensions": dims,
              "StartTime": minute, "EndTime": minute + timedelta(seconds=60), "Period": 60}
    if extended:
        kwargs["ExtendedStatistics"] = [extended]
    else:
        kwargs["Statistics"] = [statistic]
    return cw.get_metric_statistics(**kwargs)["Datapoints"]


def _close(a: float, b: float, tol: float) -> bool:
    return abs(a - b) <= tol


def _ignore_missing(fn) -> None:
    """Run a teardown call; a resource the in-body teardown already deleted is not an error."""
    try:
        fn()
    except ClientError as exc:
        if not exc.response["Error"]["Code"].startswith("NoSuch"):
            raise


def _delete_oac(cf, oac_id, *, timeout_s=120.0) -> None:
    """Delete the OAC, retrying only OriginAccessControlInUse while a just-deleted distribution
    releases it. Any other refusal is raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _ignore_missing(lambda: _delete_with_etag(cf.get_origin_access_control,
                                                      cf.delete_origin_access_control, oac_id))
            return
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "OriginAccessControlInUse"
                    or time.monotonic() > deadline):
                raise
            time.sleep(10)


def _teardown_estate(cf, subscribed, dist_ids, oac_id) -> None:
    """The whole CloudFront estate, torn down in the body on the success path; any failure raises.
    On a failing run the registered ctx.on_cleanup nets tear it down instead."""
    try:
        for dist_id in list(subscribed):
            _ignore_missing(lambda d=dist_id: cf.delete_monitoring_subscription(DistributionId=d))
            subscribed.remove(dist_id)
    finally:
        try:
            _disable_and_delete_distributions(cf, dist_ids)
        finally:
            _delete_oac(cf, oac_id)


def _await_additional_metrics_live(cw, warm_gets, dims, since, *, timeout_s=900.0,
                                   interval_s=30.0) -> None:
    """Drive warm-up traffic until the subscribed distribution has published ONE CacheHitRate point.
    Additional metrics cover only traffic from ~4 min after CreateMonitoringSubscription, so the
    measured phase waits for this polled barrier."""
    def probe():
        for get in warm_gets:
            get()
        return cw.get_metric_statistics(
            Namespace="AWS/CloudFront", MetricName="CacheHitRate", Dimensions=dims,
            StartTime=since, EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
            Period=60, Statistics=["Average"])["Datapoints"]

    _poll_until(probe, lambda d: len(d) >= 1, timeout_s=timeout_s, interval_s=interval_s,
                description="the monitoring subscription to go live (a first CacheHitRate point "
                            "for warm-up traffic)")


# ===== end helpers =====


def _error(fn) -> tuple[str, str]:
    """(code, message) of the AWS error fn raised. Raises if fn SUCCEEDS — success is never a code."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {resp!r}")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/viewing-cloudfront-metrics.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Without a monitoring subscription, a distribution publishes only its default metrics: given
    traffic identical to a subscribed twin, CacheHitRate, OriginLatency and 403ErrorRate never
    appear for it (datapoints or ListMetrics) while Requests and 4xxErrorRate match what it served.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    # CloudFront is GLOBAL and publishes every distribution metric to CloudWatch in us-east-1 only,
    # whatever region the origin is in: the documented home of a global resource's telemetry.
    cw = ctx.client("cloudwatch", region="us-east-1")

    bucket = ctx.unique_name("sim2real-xsvc-cfobs-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    warmup_key, absent_key = _WARMUP_KEY, _ABSENT_KEY
    payload = _PRESENT_BODY
    for i in range(_MAX_ROUNDS):
        s3.put_object(Bucket=bucket, Key=_round_key(i), Body=payload, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key=warmup_key, Body=b"warmup", ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cfobs-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    # One net for both distributions, registered BEFORE either create: it disables both, then
    # waits, so teardown costs the slower of the two rather than their sum.
    dist_ids: list[str] = []
    subscribed: list[str] = []
    ctx.on_cleanup(lambda: _disable_and_delete_distributions(cf, dist_ids))
    dists = {}
    for side, comment in (("A", "sim2real obs-cloudfront-1 subscribed"),
                          ("B", "sim2real obs-cloudfront-1 control, no subscription")):
        d = cf.create_distribution_with_tags(DistributionConfigWithTags={
            "DistributionConfig": _distribution_config(ctx, bucket, oac_id, comment),
            "Tags": {"Items": _TAG_SET},
        })["Distribution"]
        dist_ids.append(d["Id"])
        dists[side] = d
    a_id, b_id = dists["A"]["Id"], dists["B"]["Id"]

    _allow_cloudfront_oac(s3, bucket, [dists["A"]["ARN"], dists["B"]["ARN"]])

    cf.create_monitoring_subscription(DistributionId=a_id, MonitoringSubscription={
        "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"},
    })
    subscribed.append(a_id)
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: cf.delete_monitoring_subscription(DistributionId=a_id)))
    subscribed_at = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    a_status = cf.get_monitoring_subscription(DistributionId=a_id)["MonitoringSubscription"][
        "RealtimeMetricsSubscriptionConfig"]["RealtimeMetricsSubscriptionStatus"]
    assert a_status == "Enabled", f"A's subscription read back as {a_status!r}, not 'Enabled'"
    # The control genuinely has no subscription: the read is refused with the exact code.
    b_err = _error(lambda: cf.get_monitoring_subscription(DistributionId=b_id))
    want_b_err = ("NoSuchMonitoringSubscription", "The monitoring subscription does not exist.")
    assert b_err == want_b_err, (
        f"GetMonitoringSubscription on the unsubscribed control: expected {want_b_err!r}, "
        f"got {b_err!r}")

    window_start = subscribed_at - timedelta(minutes=1)
    _wait_distribution_deployed(cf, a_id)
    _wait_distribution_deployed(cf, b_id)

    sessions = {side: requests.Session() for side in dists}
    routes = {side: ctx.endpoint_route(d["DomainName"]) for side, d in dists.items()}
    bases = {side: url for side, (url, _) in routes.items()}
    for side, (_, route_headers) in routes.items():
        sessions[side].headers.update(route_headers)
    for side in dists:
        warm = _fetch_ok(sessions[side], f"{bases[side]}/{warmup_key}")
        assert warm.content == b"warmup", (
            f"warm-up through {side} served {warm.content[:80]!r}, not the warm-up body")

    def dims(dist_id):
        return [{"Name": "DistributionId", "Value": dist_id},
                {"Name": "Region", "Value": "Global"}]

    def warm_getter(side):
        def get() -> None:
            try:
                r = sessions[side].get(f"{bases[side]}/{warmup_key}", timeout=_HTTP_TIMEOUT_S)
            except requests.RequestException as exc:
                raise AssertionError(f"{DATAPLANE_MARKER}: warm-up request to {side} failed "
                                     f"after the edge had served: {exc!r}") from exc
            assert r.status_code == 200, (
                f"warm-up request to {side}: expected 200, got {r.status_code}")
        return get

    # Identical warm-up traffic to both sides; the barrier is A's subscription going live.
    _await_additional_metrics_live(cw, [warm_getter("A"), warm_getter("B")], dims(a_id),
                                   subscribed_at)
    def listed(metric, dist_id):
        out = []
        for page in cw.get_paginator("list_metrics").paginate(
                Namespace="AWS/CloudFront", MetricName=metric,
                Dimensions=[{"Name": "DistributionId", "Value": dist_id}]):
            out.extend(page["Metrics"])
        return out

    # ---- measured rounds: identical traffic to both sides, every response recorded ----
    # Measured on real AWS: early in a subscription, CloudFront publishes the additional
    # metrics for SOME minutes and not others. So the burst repeats once per fresh minute with
    # a FRESH present key, and the barrier is any round minute for which A's gated metrics AND
    # B's default metrics are both published: that differential barrier, not a timer, rules
    # out publication lag as the cause of B's missing gated metrics.
    rounds: dict[datetime, dict[str, list[tuple[str, int, str]]]] = {}
    first_request_at = None
    # The barrier's warm-up traffic owns the current minute; rounds start in a LATER one.
    last_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def run_round(i: int, minute: datetime) -> dict[str, list[tuple[str, int, str]]]:
        key = _round_key(i)
        rec: dict[str, list[tuple[str, int, str]]] = {"A": [], "B": []}
        for side in ("A", "B"):
            plan = [key] * (1 + _PRESENT_REPEATS) + [absent_key] * _ABSENT_REQUESTS
            for k in plan:
                try:
                    r = sessions[side].get(f"{bases[side]}/{k}", timeout=_HTTP_TIMEOUT_S)
                except requests.RequestException as exc:
                    raise AssertionError(
                        f"{DATAPLANE_MARKER}: measured request to {side} for {k!r} got no "
                        f"response from a Deployed distribution that just served: {exc!r}"
                    ) from exc
                rec[side].append((k, r.status_code, r.headers.get("X-Cache", "")))
                if k == key:
                    assert r.status_code == 200 and r.content == payload, (
                        f"{side} present key: expected 200 with the origin body, got "
                        f"{r.status_code} / {r.content[:120]!r}")
                else:
                    assert r.status_code == 403, (
                        f"{side} absent key through OAC without s3:ListBucket: expected the "
                        f"origin's 403, got {r.status_code} / {r.text[:200]!r}")
        finished = datetime.now(timezone.utc)
        assert finished.replace(second=0, microsecond=0) == minute, (
            f"round {i} spilled out of its minute ({minute.isoformat()} -> "
            f"{finished.isoformat()})")
        return rec

    def read_barrier(minute):
        return {
            "A:CacheHitRate": _minute_datapoints(cw, "CacheHitRate", dims(a_id), minute,
                                                 statistic="Average"),
            "A:403ErrorRate": _minute_datapoints(cw, "403ErrorRate", dims(a_id), minute,
                                                 statistic="Average"),
            "A:OriginLatency": _minute_datapoints(cw, "OriginLatency", dims(a_id), minute,
                                                  extended="p90"),
            "B:Requests": _minute_datapoints(cw, "Requests", dims(b_id), minute,
                                             statistic="Sum"),
            "B:4xxErrorRate": _minute_datapoints(cw, "4xxErrorRate", dims(b_id), minute,
                                                 statistic="Average"),
        }

    def ready(got, b_total) -> bool:
        if not all(len(v) >= 1 for v in got.values()):
            return False
        return float(got["B:Requests"][0]["Sum"]) >= b_total - _REQUESTS_SLACK

    # Bounded 30 s poll that RAISES at the deadline (900 s from the first measured request).
    barrier = None
    last_seen: dict = {}
    while True:
        now = datetime.now(timezone.utc)
        cur = now.replace(second=0, microsecond=0)
        if len(rounds) < _MAX_ROUNDS and cur > last_minute and 5 <= now.second <= 30:
            rounds[cur] = run_round(len(rounds), cur)
            last_minute = cur
            if first_request_at is None:
                first_request_at = time.monotonic()
        for m, rec in rounds.items():
            got = read_barrier(m)
            last_seen[m.isoformat()] = got
            if ready(got, len(rec["B"])):
                barrier = (m, got)
                break
        lists = {"list A:CacheHitRate": listed("CacheHitRate", a_id),
                 "list B:Requests": listed("Requests", b_id)}
        if barrier is not None and all(lists.values()):
            break
        if first_request_at is not None and (
                time.monotonic() - first_request_at > _METRIC_DEADLINE_S):
            raise AssertionError(
                f"timed out after {_METRIC_DEADLINE_S}s on the differential barrier: A "
                f"({a_id}) gated datapoints and B ({b_id}) default datapoints for one round "
                f"minute, plus ListMetrics for both; rounds "
                f"{ {m.isoformat(): r for m, r in rounds.items()}!r}; last read {last_seen!r}; "
                f"lists {lists!r}")
        until_next_round = 65 - datetime.now(timezone.utc).second
        time.sleep(max(1.0, min(_METRIC_INTERVAL_S, float(until_next_round))))

    minute, got = barrier
    b_rec = rounds[minute]["B"]
    b_total = len(b_rec)
    # The control must actually have served what the gated metrics describe — a miss (origin
    # fetch -> OriginLatency, CacheHitRate) and a 403 (-> 403ErrorRate) — or their absence
    # would be vacuous.
    b_misses = sum(1 for (k, _, x) in b_rec if k != absent_key and x.startswith("Miss "))
    b_403 = sum(1 for (_, s, _) in b_rec if s == 403)
    b_4xx = sum(1 for (_, s, _) in b_rec if 400 <= s < 500)
    assert b_misses >= 1 and b_403 >= 1, (
        f"the control served no miss or no 403, so absent gated metrics would prove nothing: "
        f"{b_rec!r}")
    want_b_4xx_rate = 100.0 * b_4xx / b_total

    # The control's DEFAULT metrics are published for that minute and match what it served.
    b_req = float(got["B:Requests"][0]["Sum"])
    assert abs(b_req - b_total) <= _REQUESTS_SLACK, (
        f"B Requests Sum at {minute.isoformat()}: expected {b_total} (+/-{_REQUESTS_SLACK}), "
        f"got {b_req!r}; record {b_rec!r}")
    b_4xx_rate = float(got["B:4xxErrorRate"][0]["Average"])
    assert abs(b_4xx_rate - want_b_4xx_rate) <= _RATE_TOLERANCE, (
        f"B 4xxErrorRate (a default metric) at {minute.isoformat()}: expected "
        f"{want_b_4xx_rate!r} from the record, got {b_4xx_rate!r}; record {b_rec!r}")
    b_listed = listed("Requests", b_id)

    # ---- the claim: none of the gated metrics exists for the control, in ANY minute ----
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    for metric in _GATED:
        kwargs = {"Namespace": "AWS/CloudFront", "MetricName": metric,
                  "Dimensions": dims(b_id), "StartTime": window_start, "EndTime": end,
                  "Period": 60}
        if metric == "OriginLatency":
            kwargs["ExtendedStatistics"] = ["p90"]
        else:
            kwargs["Statistics"] = ["Average"]
        points = cw.get_metric_statistics(**kwargs)["Datapoints"]
        assert points == [], (
            f"{metric} was published for the UNSUBSCRIBED control {b_id}: expected no "
            f"datapoints, got {points!r} — additional metrics must require a monitoring "
            f"subscription")
        catalogue = listed(metric, b_id)
        assert catalogue == [], (
            f"ListMetrics lists {metric} for the UNSUBSCRIBED control {b_id}: expected [], got "
            f"{catalogue!r} — while its Requests metric IS listed: {b_listed!r}")
    _teardown_estate(cf, subscribed, dist_ids, oac_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
