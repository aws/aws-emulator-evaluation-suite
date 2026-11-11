"""obs-cloudfront-1-additional-metrics-match-recorded-edge-outcomes."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cloudfront-1-additional-metrics-match-recorded-edge-outcomes"
GROUP = "metric-emission"
SERVICES = ["cloudfront", "cloudwatch"]

#: Marks a failure where the endpoint serves no edge at all, so it reads as a fidelity failure
#: rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: AWS managed cache policy "Managed-CachingOptimized". A fixed AWS-published id, identical in
#: every account, so referencing it is not a dependence on anything this account created.
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: The serving-phase shape. These are request COUNTS this check issues, not expected outcomes:
#: every expected metric value below is derived from what the edge actually answered.
_PRESENT_REPEATS = 3   # requests for the present key AFTER the first one
_ABSENT_REQUESTS = 2

#: Per-request HTTP timeout. Also the ceiling on any OriginLatency we could have caused: a request
#: that took longer than this would have raised instead of being recorded.
_HTTP_TIMEOUT_S = 15.0

#: Metric arrival: the deadline runs from the first measured request, polled every 30 s.
_METRIC_DEADLINE_S = 900.0
_METRIC_INTERVAL_S = 30.0

#: Two-sided slack on the Requests count. CloudWatch aggregation is per minute and is not
#: guaranteed pixel-exact; one request either way still catches a target that counts nothing,
#: double-counts, or counts only one key.
_REQUESTS_SLACK = 1.0

#: Rate tolerance in percentage points. One request moved into or out of either side of any rate
#: here shifts it by far more than this, so the tolerance only absorbs float formatting.
_RATE_TOLERANCE = 0.1

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
    """The whole CloudFront estate, torn down in the body on every path; any failure raises.
    The registered ctx.on_cleanup nets stay as the backstop."""
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


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/viewing-cloudfront-metrics.html
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
    """CloudFront's additional metrics for an isolated minute (CacheHitRate, Requests, 4xx/403/5xx
    rates, OriginLatency p90) equal values derived from the X-Cache headers and status codes the
    edge served, so constant, absent or mis-aggregated telemetry fails.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    # us-east-1 is not this suite's region by accident: CloudFront is a GLOBAL resource and
    # publishes every distribution metric to CloudWatch in us-east-1 only, whatever region the
    # origin or the viewer is in. This is the documented home of a global resource's telemetry.
    cw = ctx.client("cloudwatch", region="us-east-1")

    bucket = ctx.unique_name("sim2real-xsvc-cfobs-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))

    warmup_key, absent_key = _WARMUP_KEY, _ABSENT_KEY
    body = _PRESENT_BODY
    for i in range(_MAX_ROUNDS):
        s3.put_object(Bucket=bucket, Key=_round_key(i), Body=body, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key=warmup_key, Body=b"warmup", ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cfobs-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    # Registered BEFORE the create so a raise between create and registration cannot strand a
    # server-minted id; the list is filled the moment the id exists.
    dist_ids: list[str] = []
    subscribed: list[str] = []
    ctx.on_cleanup(lambda: _disable_and_delete_distributions(cf, dist_ids))
    try:
        dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
            "DistributionConfig": _distribution_config(ctx, bucket, oac_id,
                                                       "sim2real obs-cloudfront-1 subscribed"),
            "Tags": {"Items": _TAG_SET},
        })["Distribution"]
        dist_id = dist["Id"]
        dist_ids.append(dist_id)

        _allow_cloudfront_oac(s3, bucket, [dist["ARN"]])

        # Additional metrics are opt-in per distribution; enabled BEFORE any traffic so every
        # measured request is covered by the subscription.
        cf.create_monitoring_subscription(DistributionId=dist_id, MonitoringSubscription={
            "RealtimeMetricsSubscriptionConfig": {"RealtimeMetricsSubscriptionStatus": "Enabled"},
        })
        subscribed.append(dist_id)
        ctx.on_cleanup(lambda: _ignore_missing(
            lambda: cf.delete_monitoring_subscription(DistributionId=dist_id)))
        subscribed_at = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        status = cf.get_monitoring_subscription(DistributionId=dist_id)["MonitoringSubscription"][
            "RealtimeMetricsSubscriptionConfig"]["RealtimeMetricsSubscriptionStatus"]
        assert status == "Enabled", f"monitoring subscription read back as {status!r}, not 'Enabled'"

        _wait_distribution_deployed(cf, dist_id)

        session = requests.Session()
        base, route = ctx.endpoint_route(dist["DomainName"])
        session.headers.update(route)

        # Warm-up on a DIFFERENT key, in an earlier minute: it proves the edge serves (and pays DNS/TLS)
        # without touching the present key's cache state or the measured minute's counts.
        warm = _fetch_ok(session, f"{base}/{warmup_key}")
        assert warm.content == b"warmup", f"warm-up served {warm.content[:80]!r}, not the warm-up body"
        dims = [{"Name": "DistributionId", "Value": dist_id}, {"Name": "Region", "Value": "Global"}]

        def warm_get() -> None:
            try:
                r = session.get(f"{base}/{warmup_key}", timeout=_HTTP_TIMEOUT_S)
            except requests.RequestException as exc:
                raise AssertionError(f"{DATAPLANE_MARKER}: warm-up request failed after the edge had "
                                     f"served: {exc!r}") from exc
            assert r.status_code == 200, f"warm-up request: expected 200, got {r.status_code}"

        _await_additional_metrics_live(cw, [warm_get], dims, subscribed_at)
        # ---- measured rounds ----
        # Measured on real AWS: in a subscription's first minutes CloudFront publishes the
        # additional metrics for SOME minutes and not others (Requests is published for every
        # minute). So the burst is repeated, one round per fresh minute with a FRESH present key
        # (its first request is a genuine miss), each round recorded separately, and every round
        # minute that gets fully published is graded against its OWN record.
        rounds: dict[datetime, list[tuple[str, int, str]]] = {}
        graded: dict[datetime, dict] = {}
        first_request_at = None
        # The barrier's warm-up traffic owns the current minute; rounds start in a LATER one.
        last_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)

        def run_round(i: int, minute: datetime) -> tuple[list[tuple[str, int, str]], datetime]:
            """The round's record and the minute its last request finished in."""
            key = _round_key(i)
            rec: list[tuple[str, int, str]] = []

            def get(k: str) -> requests.Response:
                try:
                    r = session.get(f"{base}/{k}", timeout=_HTTP_TIMEOUT_S)
                except requests.RequestException as exc:
                    raise AssertionError(
                        f"{DATAPLANE_MARKER}: measured request for {k!r} got no response from a "
                        f"Deployed distribution that just served: {exc!r}") from exc
                rec.append((k, r.status_code, r.headers.get("X-Cache", "")))
                return r

            r = get(key)
            assert r.status_code == 200 and r.content == body, (
                f"first request for {key!r}: expected 200 with the origin body, got "
                f"{r.status_code} / {r.content[:120]!r}")
            assert rec[0][2] == "Miss from cloudfront", (
                f"the first request ever made for {key!r} must be a cache miss; X-Cache was "
                f"{rec[0][2]!r}")
            for _ in range(_PRESENT_REPEATS):
                r = get(key)
                assert r.status_code == 200 and r.content == body, (
                    f"repeat request for {key!r}: expected 200 with the origin body, got "
                    f"{r.status_code} / {r.content[:120]!r}")
            for _ in range(_ABSENT_REQUESTS):
                r = get(absent_key)
                # OAC-signed GET for a key that does not exist, against a policy granting
                # GetObject but not ListBucket: S3 will not say whether it exists, so 403.
                assert r.status_code == 403, (
                    f"absent key through OAC without s3:ListBucket: expected the origin's 403, "
                    f"got {r.status_code} / {r.text[:200]!r}")
            return rec, datetime.now(timezone.utc).replace(second=0, microsecond=0)

        def read_all(minute):
            return {
                "Requests": _minute_datapoints(cw, "Requests", dims, minute, statistic="Sum"),
                "CacheHitRate": _minute_datapoints(cw, "CacheHitRate", dims, minute,
                                                   statistic="Average"),
                "4xxErrorRate": _minute_datapoints(cw, "4xxErrorRate", dims, minute,
                                                   statistic="Average"),
                "403ErrorRate": _minute_datapoints(cw, "403ErrorRate", dims, minute,
                                                   statistic="Average"),
                "5xxErrorRate": _minute_datapoints(cw, "5xxErrorRate", dims, minute,
                                                   statistic="Average"),
                "OriginLatency": _minute_datapoints(cw, "OriginLatency", dims, minute,
                                                    extended="p90"),
            }

        def ready(got, rec) -> bool:
            if not all(len(v) == 1 for v in got.values()):
                return False
            return float(got["Requests"][0]["Sum"]) >= len(rec) - _REQUESTS_SLACK

        # Bounded poll at a 30 s cadence that RAISES at the deadline (900 s from the first measured
        # request); a new round fires whenever a fresh minute opens and none is graded yet.
        # A round whose requests spill into the next minute is not graded (no one datapoint holds
        # all of it), and the next round starts after the minute the spill reached.
        last_seen: dict = {}
        rounds_fired = 0
        while True:
            now = datetime.now(timezone.utc)
            cur = now.replace(second=0, microsecond=0)
            if (rounds_fired < _MAX_ROUNDS and cur > last_minute and 5 <= now.second <= 30):
                rec, finished_minute = run_round(rounds_fired, cur)
                rounds_fired += 1
                if finished_minute == cur:
                    rounds[cur] = rec
                last_minute = finished_minute
                if first_request_at is None:
                    first_request_at = time.monotonic()
            for m, rec in rounds.items():
                got = read_all(m)
                # CloudWatch revises a minute's datapoints while late edge data arrives, so a
                # minute is graded only once two consecutive reads return the same datapoints.
                if ready(got, rec) and last_seen.get(m.isoformat()) == got:
                    graded[m] = got
                last_seen[m.isoformat()] = got
            if graded:
                break
            if first_request_at is not None and (
                    time.monotonic() - first_request_at > _METRIC_DEADLINE_S):
                raise AssertionError(
                    f"timed out after {_METRIC_DEADLINE_S}s: no measured minute of {dist_id} got "
                    f"all of Requests/CacheHitRate/4xx/403/5xx/OriginLatency published; rounds "
                    f"{ {m.isoformat(): r for m, r in rounds.items()}!r}; last read {last_seen!r}")
            until_next_round = 65 - datetime.now(timezone.utc).second
            time.sleep(max(1.0, min(_METRIC_INTERVAL_S, float(until_next_round))))

        # ---- every fully-published minute equals what ITS round recorded ----
        for minute, got in sorted(graded.items()):
            record = rounds[minute]
            total = len(record)
            present = [x for (k, _, x) in record if k != absent_key]
            hits = sum(1 for x in present if x.startswith("Hit "))
            misses = sum(1 for x in present if x.startswith("Miss "))
            assert hits + misses == len(present), (
                f"every present-key X-Cache must be a Hit or a Miss to derive CacheHitRate; got "
                f"{present!r}")
            errors_4xx = sum(1 for (_, s, _) in record if 400 <= s < 500)
            errors_403 = sum(1 for (_, s, _) in record if s == 403)
            errors_5xx = sum(1 for (_, s, _) in record if s >= 500)
            # CloudFront's documented CacheHitRate denominator is CACHEABLE requests: error
            # responses (our 403s) are not cacheable, so the rate is over present-key requests.
            want_hit_rate = 100.0 * hits / len(present)
            want_4xx_rate = 100.0 * errors_4xx / total
            want_403_rate = 100.0 * errors_403 / total
            want_5xx_rate = 100.0 * errors_5xx / total

            req = got["Requests"][0]
            assert _close(float(req["Sum"]), float(total), _REQUESTS_SLACK), (
                f"Requests Sum at {minute.isoformat()}: expected {total} (+/-{_REQUESTS_SLACK}) — "
                f"the requests that round issued — got {req['Sum']!r}; record {record!r}")
            assert req["Unit"] == "None", f"Requests Unit: expected 'None', got {req['Unit']!r}"

            for metric, want in (("CacheHitRate", want_hit_rate), ("4xxErrorRate", want_4xx_rate),
                                 ("403ErrorRate", want_403_rate), ("5xxErrorRate", want_5xx_rate)):
                dp = got[metric][0]
                assert _close(float(dp["Average"]), want, _RATE_TOLERANCE), (
                    f"{metric} Average at {minute.isoformat()}: expected {want!r} derived from the "
                    f"recorded outcomes (hits={hits}, misses={misses}, 4xx={errors_4xx}, "
                    f"403={errors_403}, 5xx={errors_5xx}, total={total}), got {dp['Average']!r}; "
                    f"record {record!r}")
                assert dp["Unit"] == "Percent", (
                    f"{metric} Unit: expected 'Percent', got {dp['Unit']!r}")

            lat = got["OriginLatency"][0]
            p90 = float(lat["ExtendedStatistics"]["p90"])
            assert lat["Unit"] == "Milliseconds", (
                f"OriginLatency Unit: expected 'Milliseconds', got {lat['Unit']!r}")
            # Bounded by our own client timeout: a fetch slower than that would have raised.
            assert 0.0 < p90 < _HTTP_TIMEOUT_S * 1000.0, (
                f"OriginLatency p90 at {minute.isoformat()}: expected a positive latency below the "
                f"{_HTTP_TIMEOUT_S}s client timeout, got {p90!r} ms")
    except BaseException as exc:
        # Torn down in the body on every path: ctx.on_cleanup is bounded at 60 s and
        # disable -> Deployed -> delete takes minutes. A teardown error never masks this failure.
        try:
            _teardown_estate(cf, subscribed, dist_ids, oac_id)
        except BaseException as teardown_exc:
            exc.add_note(f"teardown also failed: {teardown_exc!r}")
        raise
    _teardown_estate(cf, subscribed, dist_ids, oac_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
