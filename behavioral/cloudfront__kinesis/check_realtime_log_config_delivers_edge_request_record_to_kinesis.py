"""realtime-log-config-delivers-edge-request-record-to-kinesis."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "realtime-log-config-delivers-edge-request-record-to-kinesis"
GROUP = "data-plane"
SERVICES = ["cloudfront", "kinesis"]

#: Prefix marking a FAIL as an unimplemented endpoint data plane rather than a wrong answer.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: every request must reach the origin, so the one request this check makes
#: is guaranteed to be a logged viewer request with a deterministic result type.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: The SET here is the assertion; CloudFront reorders these into its own canonical order.
_FIELDS = ["timestamp", "c-ip", "cs-uri-stem", "sc-status", "x-edge-response-result-type"]

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
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete."""
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
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
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
    """GET url until it answers 200, then return that response; raise (marked) on exhaustion."""
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


def _delete_role(iam, role_name, policy_name) -> None:
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """One edge request yields exactly one real-time log line in Kinesis, read via GetRecords.

    The line names this run's URI stem, status 200, a Miss, a viewer IP and a timestamp in-window.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/real-time-logs.html
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stream_name = ctx.unique_name("sim2real-behav-cfrtl-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: ctx.client("kinesis").delete_stream(
        StreamName=stream_name, EnforceConsumerDeletion=True))
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(
            StreamName=stream_name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=300.0, interval_s=5.0,
        description=f"kinesis stream {stream_name} to become ACTIVE before it can accept records",
    )
    stream_arn = summary["StreamARN"]
    kinesis.add_tags_to_stream(StreamName=stream_name,
                              Tags={t["Key"]: t["Value"] for t in _TAG_SET})

    role_name = ctx.unique_name("sim2real-behav-cfrtl-role-")
    policy_name = "sim2real-kinesis-put"
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real CloudFront real-time log delivery",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx.client("iam"), role_name, policy_name))
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["kinesis:DescribeStreamSummary", "kinesis:DescribeStream",
                       "kinesis:PutRecord", "kinesis:PutRecords"],
            "Resource": stream_arn,
        }],
    }))

    # CreateRealtimeLogConfig validates neither RoleARN nor StreamARN at creation, so no retry.
    log_config = cf.create_realtime_log_config(
        Name=ctx.unique_name("sim2real-behav-cfrtl-cfg-"),
        SamplingRate=100,
        Fields=_FIELDS,
        EndPoints=[{"StreamType": "Kinesis",
                    "KinesisStreamConfig": {"RoleARN": role_arn,
                                            "StreamARN": stream_arn}}],
    )["RealtimeLogConfig"]
    log_config_arn = log_config["ARN"]
    ctx.on_cleanup(lambda: cf.delete_realtime_log_config(ARN=log_config_arn))
    assert set(log_config["Fields"]) == set(_FIELDS), (
        f"CreateRealtimeLogConfig must store exactly the requested field set: expected "
        f"{sorted(_FIELDS)}, got {sorted(log_config['Fields'])}"
    )
    assert log_config["SamplingRate"] == 100, (
        f"a sampling rate below 100 would make a single-request check probabilistic: expected 100, "
        f"got {log_config['SamplingRate']}"
    )
    # CloudFront reorders Fields into its own canonical order; the log line follows that order.
    field_index = {name: i for i, name in enumerate(log_config["Fields"])}

    bucket = ctx.unique_name("sim2real-behav-cfrtl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    probe_key = f"{ctx.unique_name('probe-')}.txt"
    body = b"sim2real-realtime-log-probe"
    s3.put_object(Bucket=bucket, Key=probe_key, Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfrtl-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cfrtl-cr-"),
        "Comment": "sim2real real-time logs to kinesis",
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
            "RealtimeLogConfigArn": log_config_arn,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted. Registered AFTER the log
    # config's cleanup so LIFO deletes the distribution first — a real-time log config referenced by
    # a live distribution cannot be deleted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})
    assert account in dist["ARN"], (
        f"expected the distribution ARN to belong to the calling account {account}, got "
        f"{dist['ARN']!r}"
    )

    _allow_cloudfront_oac(s3, bucket, dist["ARN"])
    _wait_distribution_deployed(cf, dist_id)

    # The iterator is opened BEFORE the request, at the horizon of a stream this check created, so
    # the record it finds cannot predate the request and cannot belong to anything else.
    shard_id = kinesis.describe_stream(
        StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id,
        ShardIteratorType="TRIM_HORIZON")["ShardIterator"]

    edge, route_headers = ctx.endpoint_route(domain)
    session = requests.Session()
    session.headers.update(route_headers)
    window_start = time.time() - 60
    served = _fetch_ok(session, f"{edge}/{probe_key}")
    assert served.content == body, (
        f"the edge served the wrong bytes, so the record below would describe the wrong request: "
        f"expected {body!r}, got {served.content[:120]!r}"
    )
    window_end = time.time() + 60

    lines: list[str] = []
    cursor = {"it": iterator}

    def drain():
        """One GetRecords step; accumulate every log line seen so far."""
        resp = kinesis.get_records(ShardIterator=cursor["it"], Limit=1000)
        cursor["it"] = resp["NextShardIterator"]
        for record in resp["Records"]:
            # One Kinesis record may batch several log lines.
            for line in record["Data"].decode("utf-8").splitlines():
                if line:
                    lines.append(line)
        return [ln for ln in lines if probe_key in ln]

    matching = _poll_until(
        drain, lambda found: len(found) >= 1, timeout_s=300.0, interval_s=5.0,
        description=(f"a real-time log record naming {probe_key!r} to arrive in kinesis stream "
                     f"{stream_name} for the single edge request this check made"),
    )
    assert len(matching) == 1, (
        f"one viewer request must produce exactly one real-time log line naming {probe_key!r}, got "
        f"{len(matching)}: {matching!r}"
    )

    parts = matching[0].split("\t")
    assert len(parts) == len(_FIELDS), (
        f"a real-time log line must carry exactly the {len(_FIELDS)} fields this run configured "
        f"({_FIELDS}), tab-delimited; got {len(parts)} fields: {matching[0]!r}"
    )
    uri_i, status_i, result_i = (field_index["cs-uri-stem"], field_index["sc-status"],
                                  field_index["x-edge-response-result-type"])
    assert parts[uri_i] == f"/{probe_key}", (
        f"cs-uri-stem is at index {uri_i} in CloudFront's own reported order {log_config['Fields']}: "
        f"expected '/{probe_key}', got {parts[uri_i]!r}"
    )
    assert parts[status_i] == "200", (
        f"sc-status is at index {status_i} in {log_config['Fields']} and the edge answered 200: got "
        f"{parts[status_i]!r}"
    )
    assert parts[result_i] == "Miss", (
        f"x-edge-response-result-type is at index {result_i} in {log_config['Fields']} and the "
        f"behaviour disables caching, so a cold request must be a Miss: got {parts[result_i]!r}"
    )
    ts_i, ip_i = field_index["timestamp"], field_index["c-ip"]
    logged_at = float(parts[ts_i])
    assert window_start <= logged_at <= window_end, (
        f"timestamp is at index {ts_i} in {log_config['Fields']} and must fall inside this run's own "
        f"clock window [{window_start:.0f}, {window_end:.0f}], got {logged_at:.0f}"
    )
    assert parts[ip_i] != "", (
        f"c-ip is at index {ip_i} in {log_config['Fields']} and must name the viewer that made the "
        f"request, got {parts[ip_i]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
