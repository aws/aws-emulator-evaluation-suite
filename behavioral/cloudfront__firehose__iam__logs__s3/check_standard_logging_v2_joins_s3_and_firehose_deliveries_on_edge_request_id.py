"""standard-logging-v2-joins-s3-and-firehose-deliveries-on-edge-request-id."""
from __future__ import annotations

import gzip
import http.client
import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "standard-logging-v2-joins-s3-and-firehose-deliveries-on-edge-request-id"
GROUP = "log-delivery"
SERVICES = ["cloudfront", "firehose", "iam", "logs", "s3"]

#: Standard logging v2's delivery source, its destinations and the Firehose delivery stream it can
#: name are all accepted only in us-east-1, regardless of the distribution's own global scope.
_LOGS_REGION = "us-east-1"

#: Managed CachingOptimized: a repeat request for the same key can be served from cache, which is
#: what turns the second request into a Hit rather than a second Miss.
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: The join key plus the three fields the scenario pins, identical for both deliveries so the two
#: records for one request are directly comparable.
RECORD_FIELDS = ["x-edge-request-id", "cs-uri-stem", "sc-status", "x-edge-result-type"]

#: The longest wait for a distribution to reach Deployed, in the body or in teardown. Declared
#: > 300 s so the derived per-check and teardown budgets lift; a ceiling to fail at, never a
#: latency claim.
_DEPLOYED_DEADLINE_S = 900

_TAGS = {"sim2real": "behavioral"}
_TAG_LIST = [{"Key": "sim2real", "Value": "behavioral"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    """Bounded retry that RAISES on timeout, quoting the last value probed."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last: {last!r})")


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _bounded(ctx, timeout_s: float) -> float:
    """``timeout_s``, cut to the time the runner leaves this body or teardown, less a margin."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 15.0))


def _wait_distribution_deployed(ctx, cf, dist_id, *, interval_s=15.0) -> str:
    """Poll GetDistribution to Status=Deployed; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=_bounded(ctx, _DEPLOYED_DEADLINE_S),
                interval_s=interval_s, description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _retire_distribution(ctx, cf, dist_id) -> None:
    """Disable if enabled, wait for Deployed, delete; tolerates a distribution already removed."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchDistribution":
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc
        return
    cfg = resp["DistributionConfig"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    etag = _wait_distribution_deployed(ctx, cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_oac_if_present(cf, oac_id) -> None:
    try:
        cf.delete_origin_access_control(Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchOriginAccessControl":
            raise RuntimeError(f"cloudfront origin access control {oac_id}: {exc!r}") from exc


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s) in {bucket}: {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _delete_delivery_if_present(logs, delivery_id) -> None:
    try:
        logs.delete_delivery(id=delivery_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"logs delivery {delivery_id}: {exc!r}") from exc


def _delete_delivery_destination_if_present(logs, name) -> None:
    try:
        logs.delete_delivery_destination(name=name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"logs delivery destination {name}: {exc!r}") from exc


def _delete_delivery_source_if_present(logs, name) -> None:
    try:
        logs.delete_delivery_source(name=name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"logs delivery source {name}: {exc!r}") from exc


def _delete_stream_if_present(firehose, name, *, timeout_s=90.0) -> None:
    """DeleteDeliveryStream returns before the stream is actually gone; wait it out so the account
    audit right after this check never finds it still DELETING."""
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "ResourceNotFoundException":
            raise RuntimeError(f"firehose delivery stream {name}: {exc!r}") from exc
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except Exception as exc:  # noqa: BLE001
            if _code(exc) == "ResourceNotFoundException":
                return
            raise RuntimeError(f"firehose delivery stream {name}: {exc!r}") from exc
        time.sleep(5)
    raise RuntimeError(f"firehose delivery stream {name}: still present {timeout_s}s after delete")


def _delete_iam_role(iam, role_name, policy_name) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchEntity":
            raise RuntimeError(f"iam role policy {role_name}/{policy_name}: {exc!r}") from exc
    try:
        iam.delete_role(RoleName=role_name)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchEntity":
            raise RuntimeError(f"iam role {role_name}: {exc!r}") from exc


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


def _get(url, headers, verify):
    """One raw GET through the edge: (status, lower-cased headers); a transport failure is (None, {})."""
    req = urllib.request.Request(url, headers={"User-Agent": "sim2real-behavioral", **headers})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_https_context(verify)) as resp:
            resp.read()
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}
    except (urllib.error.URLError, http.client.HTTPException, OSError):
        return None, {}


def _request(base_url, path, route_headers, expect_status, *, verify, timeout_s=240.0):
    """GET `path` until the edge answers `expect_status` carrying an X-Amz-Cf-Id; return
    (request_id, result), `result` being the first word of X-Cache."""
    status, headers = _poll_until(
        lambda: _get(base_url + path, route_headers, verify),
        lambda r: r[0] == expect_status and "x-amz-cf-id" in r[1],
        timeout_s=timeout_s, interval_s=5.0,
        description=f"HTTP {expect_status} with an X-Amz-Cf-Id from {path}")
    x_cache = headers.get("x-cache", "")
    assert x_cache.endswith(" from cloudfront"), f"the edge must report X-Cache for {path}, got {x_cache!r}"
    return headers["x-amz-cf-id"], x_cache.split(" ", 1)[0]


def _request_until_result(base_url, path, route_headers, expect_status, expect_result, *, verify,
                          timeout_s=120.0, interval_s=3.0):
    """Repeat `_request` until one attempt reports `expect_result` (anycast can route a repeat
    request to a different edge location, which Misses again); return that attempt's pair."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _request(base_url, path, route_headers, expect_status, verify=verify)
        if last[1] == expect_result:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for a {expect_result} on {path} (last: {last!r})")


def _json_records(s3, bucket) -> dict:
    """Every JSON record landed in `bucket`, keyed by x-edge-request-id."""
    out = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if body[:2] == b"\x1f\x8b":  # delivered gzip-compressed, by default
                body = gzip.decompress(body)
            for line in body.decode("utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                out[rec.get("x-edge-request-id")] = rec
    return out


def _create_firehose_role(ctx, iam, bucket_arn) -> str:
    """An IAM role Firehose assumes to write into `bucket_arn`; returns its ARN."""
    role_name = ctx.unique_name("sim2real-behav-fhrole-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=_TAG_LIST)["Role"]
    policy_name = ctx.unique_name("sim2real-behav-fhpolicy-")
    ctx.on_cleanup(lambda: _delete_iam_role(iam, role_name, policy_name))
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            # The S3 permissions Firehose documents for an S3 destination (multipart writes included).
            "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                       "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"]}]}))
    return role["Arn"]


def _create_delivery_stream_with_retry(firehose, stream_name, role_arn, bucket_arn, *, timeout_s=90.0):
    dest = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name, DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest, Tags=_TAG_LIST)
            return
        except firehose.exceptions.InvalidArgumentException as exc:
            # the role's trust policy can take a few seconds to propagate to Firehose.
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateDeliveryStream kept failing on IAM propagation: {last_err!r}")


def _wait_stream_active(firehose, stream_name, *, timeout_s=120.0) -> None:
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"]["DeliveryStreamStatus"],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"), timeout_s=timeout_s, interval_s=5.0,
        description=f"delivery stream {stream_name} to leave CREATING")
    assert status == "ACTIVE", f"delivery stream {stream_name} ended in status {status!r}"


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Standard logging v2 fans one distribution's access log out to an S3 bucket and a Firehose
    stream, and the record each writes for the same edge request is identical.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    s3_east = ctx.client("s3", region=_LOGS_REGION)
    iam = ctx.client("iam")
    firehose = ctx.client("firehose", region=_LOGS_REGION)
    logs = ctx.client("logs", region=_LOGS_REGION)

    # --- origin: a private bucket served through an origin access control ----------------------
    origin_bucket = ctx.unique_name("sim2real-behav-cflog-origin-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=origin_bucket)
    else:
        s3.create_bucket(Bucket=origin_bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, origin_bucket))
    key = f"{ctx.unique_name('obj-')}.txt"
    body = b"sim2real-standard-logging-v2-s3-firehose-probe"
    s3.put_object(Bucket=origin_bucket, Key=key, Body=body, ContentType="text/plain")
    missing_key = f"{ctx.unique_name('absent-')}.txt"

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cflog-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always", "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac_if_present(cf, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cflog-cr-"),
        "Comment": "sim2real standard logging v2 to s3 and firehose",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin", "DomainName": f"{origin_bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": oac_id}]},
        "DefaultCacheBehavior": {"TargetOriginId": "s3origin", "ViewerProtocolPolicy": "allow-all",
                                 "CachePolicyId": MANAGED_CACHING_OPTIMIZED},
    })["Distribution"]
    dist_id, dist_arn, domain = dist["Id"], dist["ARN"], dist["DomainName"]
    partition = dist_arn.split(":")[1]
    ctx.on_cleanup(lambda: _retire_distribution(ctx, cf, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": _TAG_LIST})
    s3.put_bucket_policy(Bucket=origin_bucket, Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject", "Resource": f"arn:{partition}:s3:::{origin_bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}}}]}))

    # --- the S3 destination: a bucket only this delivery writes to ------------------------------
    s3_dest_bucket = ctx.unique_name("sim2real-behav-cflog-s3dst-").lower()
    s3_east.create_bucket(Bucket=s3_dest_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3_east, s3_dest_bucket))
    source_name = ctx.unique_name("sim2real-behav-cflog-src-")
    s3_east.put_bucket_policy(Bucket=s3_dest_bucket, Policy=json.dumps({
        "Version": "2012-10-17", "Id": "AWSLogDeliveryWrite20150319", "Statement": [{
            "Sid": "AWSLogDeliveryWrite", "Effect": "Allow",
            "Principal": {"Service": "delivery.logs.amazonaws.com"}, "Action": "s3:PutObject",
            "Resource": f"arn:{partition}:s3:::{s3_dest_bucket}/AWSLogs/{ctx.account}/*",
            "Condition": {
                "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceAccount": ctx.account},
                "ArnLike": {"aws:SourceArn":
                            f"arn:{partition}:logs:{_LOGS_REGION}:{ctx.account}:delivery-source:{source_name}"}}}]}))

    # --- the Firehose destination: a DirectPut stream landing in its own bucket ------------------
    fh_dest_bucket = ctx.unique_name("sim2real-behav-cflog-fhdst-").lower()
    s3_east.create_bucket(Bucket=fh_dest_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3_east, fh_dest_bucket))
    fh_dest_arn = f"arn:{partition}:s3:::{fh_dest_bucket}"
    role_arn = _create_firehose_role(ctx, iam, fh_dest_arn)
    stream_name = ctx.unique_name("sim2real-behav-cflog-fhstream-")
    _create_delivery_stream_with_retry(firehose, stream_name, role_arn, fh_dest_arn)
    ctx.on_cleanup(lambda: _delete_stream_if_present(firehose, stream_name))
    _wait_stream_active(firehose, stream_name)
    stream_arn = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"]["DeliveryStreamARN"]

    # --- the delivery wiring: one ACCESS_LOGS source feeding both destinations -------------------
    src = logs.put_delivery_source(name=source_name, resourceArn=dist_arn, logType="ACCESS_LOGS",
                                   tags=_TAGS)["deliverySource"]
    ctx.on_cleanup(lambda: _delete_delivery_source_if_present(logs, source_name))
    assert src["service"] == "cloudfront" and src["resourceArns"] == [dist_arn], (
        f"the delivery source must be a cloudfront ACCESS_LOGS source naming this distribution, got {src!r}")

    s3_dest_name = ctx.unique_name("sim2real-behav-cflog-s3ddst-")
    s3_dest = logs.put_delivery_destination(
        name=s3_dest_name, outputFormat="json", tags=_TAGS,
        deliveryDestinationConfiguration={"destinationResourceArn": f"arn:{partition}:s3:::{s3_dest_bucket}"},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: _delete_delivery_destination_if_present(logs, s3_dest_name))
    assert s3_dest["deliveryDestinationType"] == "S3", (
        f"an S3 bucket ARN must make an S3 destination, got {s3_dest['deliveryDestinationType']!r}")

    fh_dest_name = ctx.unique_name("sim2real-behav-cflog-fhddst-")
    fh_dest = logs.put_delivery_destination(
        name=fh_dest_name, outputFormat="json", tags=_TAGS,
        deliveryDestinationConfiguration={"destinationResourceArn": stream_arn},
    )["deliveryDestination"]
    ctx.on_cleanup(lambda: _delete_delivery_destination_if_present(logs, fh_dest_name))
    assert fh_dest["deliveryDestinationType"] == "FH", (
        f"a Firehose stream ARN must make an FH destination, got {fh_dest['deliveryDestinationType']!r}")

    s3_delivery = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=s3_dest["arn"],
                                       recordFields=RECORD_FIELDS, tags=_TAGS)["delivery"]
    ctx.on_cleanup(lambda: _delete_delivery_if_present(logs, s3_delivery["id"]))
    fh_delivery = logs.create_delivery(deliverySourceName=source_name, deliveryDestinationArn=fh_dest["arn"],
                                       recordFields=RECORD_FIELDS, tags=_TAGS)["delivery"]
    ctx.on_cleanup(lambda: _delete_delivery_if_present(logs, fh_delivery["id"]))
    assert {s3_delivery["deliveryDestinationType"], fh_delivery["deliveryDestinationType"]} == {"S3", "FH"}, (
        f"the two deliveries from one source must target S3 and FH, got "
        f"{s3_delivery['deliveryDestinationType']!r} and {fh_delivery['deliveryDestinationType']!r}")

    _wait_distribution_deployed(ctx, cf, dist_id)

    # --- three requests through the edge: a miss, a cache hit, and a 404 on an absent key --------
    base, route_headers = ctx.endpoint_route(domain)
    expected = {}
    rid, result = _request_until_result(base, f"/{key}", route_headers, 200, "Miss", verify=ctx.http_verify)
    expected[rid] = (f"/{key}", "200", "Miss")

    rid, result = _request_until_result(base, f"/{key}", route_headers, 200, "Hit", verify=ctx.http_verify)
    expected[rid] = (f"/{key}", "200", "Hit")

    # The OAC-scoped bucket policy grants only s3:GetObject, no s3:ListBucket, so S3 answers a
    # missing key with 403 rather than disclosing its absence through a 404.
    rid, result = _request_until_result(base, f"/{missing_key}", route_headers, 403, "Error",
                                        verify=ctx.http_verify)
    expected[rid] = (f"/{missing_key}", "403", "Error")

    assert len(expected) == 3, (
        f"three distinct requests must mint three distinct X-Amz-Cf-Id values, got {sorted(expected)}")

    # --- both deliveries carry a record for every request, joined on x-edge-request-id -----------
    s3_records = _poll_until(lambda: _json_records(s3_east, s3_dest_bucket), lambda r: set(expected) <= set(r),
                             timeout_s=900.0, interval_s=20.0,
                             description=f"the S3 destination to carry records for {sorted(expected)}")
    fh_records = _poll_until(lambda: _json_records(s3_east, fh_dest_bucket), lambda r: set(expected) <= set(r),
                             timeout_s=900.0, interval_s=20.0,
                             description=f"the Firehose-delivered object to carry records for {sorted(expected)}")

    for rid, (stem, status, result_type) in expected.items():
        for dest_label, records in (("S3", s3_records), ("Firehose", fh_records)):
            rec = records[rid]
            assert set(rec) == set(RECORD_FIELDS), (
                f"{dest_label} record {rid} must carry exactly the configured fields "
                f"{RECORD_FIELDS}, got keys {sorted(rec)}")
            assert rec["cs-uri-stem"] == stem, (
                f"{dest_label} record {rid} cs-uri-stem: expected {stem!r}, got {rec['cs-uri-stem']!r}")
            assert rec["sc-status"] == status, (
                f"{dest_label} record {rid} sc-status: expected {status!r}, got {rec['sc-status']!r}")
            assert rec["x-edge-result-type"] == result_type, (
                f"{dest_label} record {rid} x-edge-result-type: expected {result_type!r}, got "
                f"{rec['x-edge-result-type']!r}")
        assert s3_records[rid] == fh_records[rid], (
            f"request {rid} must carry the identical record through both destinations, got "
            f"S3={s3_records[rid]!r} vs Firehose={fh_records[rid]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
