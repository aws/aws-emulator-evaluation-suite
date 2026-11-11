"""obs-cloudfront-3-vended-access-logs-match-requests-and-stop-after-delete-delivery."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "obs-cloudfront-3-vended-access-logs-match-requests-and-stop-after-delete-delivery"
GROUP = "log-delivery"
SERVICES = ["cloudfront", "logs"]

# AWS behaviour this check relies on:
#   * PutDeliverySource(logType=ACCESS_LOGS, resourceArn=<distribution ARN>) is accepted ONLY in
#     us-east-1; the same call in us-west-2 is ValidationException "PutDeliverySource action is not
#     supported for this LogType in region us-west-2". So the logs client here is pinned to
#     us-east-1 on purpose: CloudFront is a global service whose vended-log plane lives there.
#   * One delivery source may feed TWO log-group destinations at once (two CreateDelivery calls on
#     the same source both succeed). That is what makes the absence assertion below a differential
#     barrier rather than a sleep.
#   * CreateDelivery to a log group attaches a LOG-GROUP-scoped resource policy
#     (policyScope=RESOURCE, Sid AWSLogDeliveryWrite1); the account-level resource-policy list is
#     untouched, so this check mutates no account-global singleton.

#: Managed CachingDisabled: every viewer request goes to the origin, so each one is a distinct,
#: deterministic log record.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: The record fields this delivery asks for. x-edge-request-id is the join key: CloudFront returns
#: the same value to the viewer as the X-Amz-Cf-Id response header.
RECORD_FIELDS = ["date", "time", "cs-uri-stem", "sc-status", "x-edge-result-type", "x-edge-request-id"]

#: The vended-log delivery plane for CloudFront exists only in us-east-1 (see above).
DELIVERY_REGION = "us-east-1"

#: Consecutive post-delete batches that must reach the barrier and NOT the primary.
CLEAN_RUN = 2
#: Upper bound on post-delete batches before "delivery never stopped" is the verdict.
MAX_BATCHES = 8

_TAGS = {"sim2real": "obs-cloudfront-3"}


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    """Bounded poll that RAISES on timeout, quoting the last value seen."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last: {last!r})")


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the AWS error `fn` raised. An unexpected SUCCESS raises — never a
    falsy sentinel."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 — botocore ClientError carries .response
        resp = getattr(exc, "response", None)
        if not resp:
            raise
        return resp["Error"]["Code"], resp["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _wait_deployed(cf, dist_id, timeout_s=1500.0) -> str:
    holder = {}

    def probe():
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=15.0,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _teardown_distributions(cf, dist_ids, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete; called from the check body on the success path.

    ctx cleanups are bounded at 60 s, far below one CloudFront disable->Deployed cycle."""
    for dist_id in dist_ids:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    for dist_id in dist_ids:
        cf.delete_distribution(Id=dist_id, IfMatch=_wait_deployed(cf, dist_id, timeout_s))


def _release_distribution(cf, dist_id) -> None:
    """Failure-path net, a few calls only: delete if already disabled and Deployed, else disable
    and report."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchDistribution":
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc
        return
    try:
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled by cleanup, delete pending"
            )
        cur = cf.get_distribution(Id=dist_id)
        if cur["Distribution"]["Status"] != "Deployed":
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled, still deploying, delete pending"
            )
        cf.delete_distribution(Id=dist_id, IfMatch=cur["ETag"])
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc


def _retry_in_use(fn, timeout_s=120.0) -> None:
    """A dependent of a just-deleted distribution can briefly still read as *InUse."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if not _code(exc).endswith("InUse") or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_oac(cf, oac_id) -> None:
    cf.delete_origin_access_control(Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])


def _delete_oac_if_present(cf, oac_id) -> None:
    try:
        _delete_oac(cf, oac_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchOriginAccessControl":
            raise RuntimeError(
                f"cloudfront origin access control {oac_id}: {exc!r}"
            ) from exc


def _create_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _oac_policy(bucket, dist_arn) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    })


def _get(url, route_headers, verify=True):
    """One raw GET through the edge: (status, lower-cased headers). Transport errors -> (None, {})."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "sim2real-obs-cloudfront-3", **route_headers})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_https_context(verify)) as resp:
            resp.read()
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}
    except (urllib.error.URLError, OSError):
        return None, {}


def _request(url, route_headers, expect_status, *, timeout_s=240.0, verify=True):
    """GET until the edge answers `expect_status` with an X-Amz-Cf-Id; return (request_id, result).

    `result` is the first word of X-Cache ('Miss', 'Hit', 'Error'), which is what the edge itself
    told the viewer — the log record's x-edge-result-type must agree with it.
    """
    status, headers = _poll_until(
        lambda: _get(url, route_headers, verify=verify),
        lambda r: r[0] == expect_status and "x-amz-cf-id" in r[1],
        timeout_s=timeout_s, interval_s=5.0,
        description=f"HTTP {expect_status} with an X-Amz-Cf-Id from {url}")
    x_cache = headers.get("x-cache", "")
    assert x_cache.endswith(" from cloudfront"), (
        f"the edge must say how it served {url} in X-Cache, got {x_cache!r}")
    return headers["x-amz-cf-id"], x_cache.split(" ", 1)[0]


def _records(logs, group) -> dict:
    """Every JSON record delivered to `group`, keyed by x-edge-request-id.

    Read stream by stream with GetLogEvents from the head rather than FilterLogEvents, whose search
    over recently ingested events is not guaranteed complete — an incomplete read would make the
    absence assertion below pass for the wrong reason.
    """
    out = {}
    for page in logs.get_paginator("describe_log_streams").paginate(logGroupName=group):
        for stream in page.get("logStreams", []):
            token = None
            while True:
                kw = {"nextToken": token} if token else {"startFromHead": True}
                resp = logs.get_log_events(logGroupName=group, logStreamName=stream["logStreamName"], **kw)
                for ev in resp.get("events", []):
                    rec = json.loads(ev["message"])
                    out[rec.get("x-edge-request-id")] = rec
                if resp.get("nextForwardToken") in (None, token):
                    break
                token = resp["nextForwardToken"]
    return out


def _delete_delivery_if_present(logs, delivery_id) -> None:
    """Teardown for a delivery the check body may already have deleted on purpose."""
    try:
        logs.delete_delivery(id=delivery_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"logs delivery {delivery_id}: {exc!r}") from exc


def _delete_delivery_source_if_present(logs, name) -> None:
    """Teardown for a delivery source the check body deletes on its success path."""
    try:
        logs.delete_delivery_source(name=name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"logs delivery source {name}: {exc!r}") from exc


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """CloudFront vended access logs record each served request (joined on x-edge-request-id), and
    stop after DeleteDelivery while a sibling delivery from the same source keeps flowing.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    logs = ctx.client("logs", region=DELIVERY_REGION)
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- origin: a private bucket served through OAC ---------------------------------------------
    bucket = ctx.unique_name("sim2real-obs3-cwl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    key = f"{ctx.unique_name('obj-')}.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-obs-cloudfront-3", ContentType="text/plain")
    missing_key = f"{ctx.unique_name('absent-')}.txt"

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-obs3-cwl-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always", "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac_if_present(cf, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-obs3-cwl-"),
        "Comment": "sim2real obs-cloudfront-3 vended access logs",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3", "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {"TargetOriginId": "s3", "ViewerProtocolPolicy": "allow-all",
                                 "CachePolicyId": MANAGED_CACHING_DISABLED},
    })["Distribution"]
    dist_id, dist_arn, domain = dist["Id"], dist["ARN"], dist["DomainName"]
    ctx.on_cleanup(lambda: _release_distribution(cf, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": k, "Value": v} for k, v in _TAGS.items()]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_oac_policy(bucket, dist_arn))

    # --- the vended-log wiring: one source, two log-group destinations --------------------------
    groups, dest_arns = [], []
    for side in ("primary", "barrier"):
        group = f"/sim2real/obs-cloudfront-3/{ctx.unique_name(side + '-')}"
        logs.create_log_group(logGroupName=group, tags=_TAGS)
        ctx.on_cleanup(lambda g=group: logs.delete_log_group(logGroupName=g))
        groups.append(group)

    source_name = ctx.unique_name("sim2real-obs3-src-")
    src = logs.put_delivery_source(name=source_name, resourceArn=dist_arn, logType="ACCESS_LOGS",
                                   tags=_TAGS)["deliverySource"]
    ctx.on_cleanup(lambda: _delete_delivery_source_if_present(logs, source_name))
    assert src["service"] == "cloudfront" and src["resourceArns"] == [dist_arn], (
        f"the delivery source must bind the distribution as a cloudfront resource, got {src!r}")

    for group in groups:
        dest_name = ctx.unique_name("sim2real-obs3-dst-")
        dest = logs.put_delivery_destination(
            name=dest_name, outputFormat="json", tags=_TAGS,
            deliveryDestinationConfiguration={
                "destinationResourceArn": f"arn:aws:logs:{DELIVERY_REGION}:{account}:log-group:{group}"},
        )["deliveryDestination"]
        ctx.on_cleanup(lambda n=dest_name: logs.delete_delivery_destination(name=n))
        assert dest["deliveryDestinationType"] == "CWL", (
            f"a log-group ARN must make a CWL destination, got {dest['deliveryDestinationType']!r}")
        dest_arns.append(dest["arn"])

    delivery_ids = []
    for dest_arn in dest_arns:
        d = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=dest_arn,
                                 recordFields=RECORD_FIELDS, tags=_TAGS)["delivery"]
        ctx.on_cleanup(lambda i=d["id"]: _delete_delivery_if_present(logs, i))
        delivery_ids.append(d["id"])
    primary_group, barrier_group = groups
    primary_delivery = delivery_ids[0]

    _wait_deployed(cf, dist_id)

    # --- phase 1: three distinct requests, both deliveries live ---------------------------------
    base, route_headers = ctx.endpoint_route(domain)
    phase1 = {}
    for path, status in ((f"/{key}", 200), (f"/{key}", 200), (f"/{missing_key}", 403)):
        rid, result = _request(base + path, route_headers, status, verify=ctx.http_verify)
        phase1[rid] = (path, status, result)
    assert len(phase1) == 3, f"three requests must mint three distinct X-Amz-Cf-Id values, got {phase1!r}"
    assert {v[2] for v in phase1.values()} == {"Miss", "Error"}, (
        f"CachingDisabled 200s must be Miss and an OAC-denied object an Error, got {phase1!r}")

    for group in groups:
        got = _poll_until(lambda g=group: _records(logs, g), lambda r: set(phase1) <= set(r),
                          timeout_s=900.0, interval_s=15.0,
                          description=f"records for all three phase-1 request ids in {group}")
        for rid, (path, status, result) in phase1.items():
            rec = got[rid]
            assert set(rec) == set(RECORD_FIELDS), (
                f"a JSON record must carry exactly the configured recordFields {RECORD_FIELDS}, "
                f"got keys {sorted(rec)} in {group}")
            assert rec["cs-uri-stem"] == path, (
                f"record {rid} cs-uri-stem: expected {path!r}, got {rec['cs-uri-stem']!r}")
            assert str(rec["sc-status"]) == str(status), (
                f"record {rid} sc-status: expected {status}, got {rec['sc-status']!r}")
            assert rec["x-edge-result-type"] == result, (
                f"record {rid} x-edge-result-type must equal what X-Cache told the viewer "
                f"({result!r}), got {rec['x-edge-result-type']!r}")

    # --- DeleteDelivery on the primary only -----------------------------------------------------
    logs.delete_delivery(id=primary_delivery)
    expected = ("ResourceNotFoundException", "Requested Delivery does not exist in this account.")
    got = _error(lambda: logs.get_delivery(id=primary_delivery))
    assert got == expected, f"GetDelivery on a deleted delivery must be {expected!r}, got {got!r}"
    assert logs.get_delivery(id=delivery_ids[1])["delivery"]["deliveryDestinationArn"] == dest_arns[1], (
        "deleting one delivery must leave the sibling delivery on the same source intact")
    # Repeat delete of the same id is a ResourceNotFoundException, not an idempotent 200.
    expected = ("ResourceNotFoundException", "Requested Delivery does not exist in this account.")
    got = _error(lambda: logs.delete_delivery(id=primary_delivery))
    assert got == expected, f"a second DeleteDelivery on the same id must be {expected!r}, got {got!r}"

    # --- after the delete: batches until the primary has stayed dark behind the barrier ---------
    # DeleteDelivery is eventually effective: a batch sent seconds after it can still land in the
    # primary group. So the contract is convergence: leaking batches form a prefix, and once
    # delivery stops it stays stopped for CLEAN_RUN consecutive batches the barrier carried.
    batches = []
    clean_run = 0
    while clean_run < CLEAN_RUN:
        assert len(batches) < MAX_BATCHES, (
            f"the primary log group still received records {len(batches)} batches after "
            f"DeleteDelivery; leaked per batch: {[sorted(set(b) & set(_records(logs, primary_group))) for b in batches]}")
        batch = {}
        for path, status in ((f"/{key}", 200), (f"/{missing_key}", 403), (f"/{key}", 200)):
            rid, result = _request(base + path, route_headers, status, verify=ctx.http_verify)
            batch[rid] = (path, status, result)
        barrier = _poll_until(lambda: _records(logs, barrier_group), lambda r: set(batch) <= set(r),
                              timeout_s=900.0, interval_s=15.0,
                              description=f"barrier delivery to carry the post-delete request ids {sorted(batch)}")
        for rid, (path, _status, _result) in batch.items():
            assert barrier[rid]["cs-uri-stem"] == path, (
                f"barrier record {rid} cs-uri-stem: expected {path!r}, got {barrier[rid]['cs-uri-stem']!r}")
        batches.append(batch)
        clean_run = 0 if set(batch) & set(_records(logs, primary_group)) else clean_run + 1

    # Final read, after the last barrier: a batch judged clean earlier must not have leaked since.
    primary = _records(logs, primary_group)
    leaked = [bool(set(b) & set(primary)) for b in batches]
    first_clean = leaked.index(False)
    assert not any(leaked[first_clean:]), (
        f"once DeleteDelivery took effect the primary must stay dark, but leaks per batch were "
        f"{leaked} (batch order) — a later batch reached the deleted delivery")
    assert set(phase1) <= set(primary), (
        f"DeleteDelivery must not purge records already delivered: missing {sorted(set(phase1) - set(primary))}")

    # The slow distribution teardown runs in the body (see _teardown_distributions).
    _delete_delivery_if_present(logs, delivery_ids[1])
    logs.delete_delivery_source(name=source_name)
    _teardown_distributions(cf, [dist_id])
    _retry_in_use(lambda: _delete_oac(cf, oac_id))


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
