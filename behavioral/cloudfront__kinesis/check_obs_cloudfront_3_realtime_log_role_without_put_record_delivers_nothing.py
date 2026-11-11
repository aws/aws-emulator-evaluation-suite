"""obs-cloudfront-3-realtime-log-role-without-put-record-delivers-nothing."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "obs-cloudfront-3-realtime-log-role-without-put-record-delivers-nothing"
GROUP = "log-delivery"
SERVICES = ["cloudfront", "kinesis"]

# CreateRealtimeLogConfig validates neither role permissions nor assumability at create time, so the
# broken config below is ACCEPTED — the failure exists only at delivery time, which is the point.

#: Every request reaches the origin, so each viewer request is one deterministic log record.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: The FIELD SET is the contract; CloudFront reorders it, so positions come from the config response.
FIELDS = ["timestamp", "cs-uri-stem", "sc-status", "x-edge-request-id"]

#: How long the control stream is polled for every one of its records.
WINDOW_S = 300.0
#: Requests sent to each side; the control must log every one.
_ROUNDS = 3
#: The least the broken stream is held empty after the control's last record; above it the hold
#: is 3x the latency the control measured on the same distribution.
_ABSENCE_FLOOR_S = 10.0

_TAGS = [{"Key": "sim2real", "Value": "obs-cloudfront-3"}]
_DESCRIBE = ["kinesis:DescribeStreamSummary", "kinesis:DescribeStream"]
_PUT = ["kinesis:PutRecord", "kinesis:PutRecords"]


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last: {last!r})")


def _dist_status(cf, dist_id):
    r = cf.get_distribution(Id=dist_id)
    return r["Distribution"]["Status"], r["ETag"]


def _wait_deployed(cf, dist_id, timeout_s=1500.0) -> str:
    return _poll_until(lambda: _dist_status(cf, dist_id), lambda s: s[0] == "Deployed",
                       timeout_s=timeout_s, interval_s=15.0,
                       description=f"distribution {dist_id} to reach Deployed")[1]


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _teardown_distributions(cf, dist_ids, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete — called from the check BODY on the success path.

    The engine bounds ctx cleanups at 60 s on a daemon thread
    it then abandons, far below one CloudFront disable->Deployed cycle. A blocking teardown
    registered with ctx.on_cleanup therefore never finishes AND strands every cleanup behind it.
    """
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


def _delete_rtl_if_present(cf, arn) -> None:
    try:
        cf.delete_realtime_log_config(ARN=arn)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchRealtimeLogConfig":
            raise RuntimeError(f"cloudfront real-time log config {arn}: {exc!r}") from exc


def _create_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _delete_role(iam, role_name) -> None:
    for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


def _get(url, route_headers, verify=True):
    try:
        req = urllib.request.Request(url, headers=route_headers)
        with urllib.request.urlopen(req, timeout=20, context=_https_context(verify)) as resp:
            resp.read()
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}
    except (urllib.error.URLError, OSError):
        return None, {}


def _served(ctx, published) -> str:
    """GET until 200 with an X-Amz-Cf-Id; return that request id."""
    url, route_headers = ctx.endpoint_route(published)
    _status, headers = _poll_until(lambda: _get(url, route_headers, verify=ctx.http_verify),
                                   lambda r: r[0] == 200 and "x-amz-cf-id" in r[1],
                                   timeout_s=240.0, interval_s=5.0, description=f"HTTP 200 from {url}")
    return headers["x-amz-cf-id"]


class _Reader:
    """Accumulates every record GetRecords returns from one single-shard stream."""

    def __init__(self, kinesis, stream_name):
        self.kinesis = kinesis
        shard = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]
        self.it = kinesis.get_shard_iterator(StreamName=stream_name, ShardId=shard,
                                             ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
        self.records = 0
        self.lines: list[str] = []

    def drain(self):
        resp = self.kinesis.get_records(ShardIterator=self.it, Limit=1000)
        self.it = resp["NextShardIterator"]
        for rec in resp["Records"]:
            self.records += 1
            self.lines += [ln for ln in rec["Data"].decode("utf-8").splitlines() if ln]
        return self


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:metrics",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A real-time log config whose role lacks kinesis:PutRecord(s) is accepted yet delivers zero
    records, while an identical control config with the permission delivers every request; granting
    the missing permission then makes the same stream receive.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    # --- two streams, two roles: identical except the broken role has no PutRecord(s) -----------
    sides = {}
    for side in ("control", "broken"):
        name = ctx.unique_name(f"sim2real-obs3-rtl-{side}-")
        kinesis.create_stream(StreamName=name, ShardCount=1)
        ctx.on_cleanup(lambda n=name: kinesis.delete_stream(StreamName=n, EnforceConsumerDeletion=True))
        sides[side] = {"stream": name}
    for side, s in sides.items():
        summary = _poll_until(
            lambda n=s["stream"]: kinesis.describe_stream_summary(StreamName=n)["StreamDescriptionSummary"],
            lambda d: d["StreamStatus"] == "ACTIVE", timeout_s=300.0, interval_s=5.0,
            description=f"kinesis stream {s['stream']} to become ACTIVE")
        s["arn"] = summary["StreamARN"]
        kinesis.add_tags_to_stream(StreamName=s["stream"], Tags={t["Key"]: t["Value"] for t in _TAGS})

        role_name = ctx.unique_name(f"sim2real-obs3-rtl-{side}-")
        s["role_arn"] = iam.create_role(
            RoleName=role_name, Description="sim2real obs-cloudfront-3 real-time log delivery", Tags=_TAGS,
            AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "sts:AssumeRole"}]}),
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda r=role_name: _delete_role(iam, r))
        s["role"] = role_name
        actions = _DESCRIBE + (_PUT if side == "control" else [])
        iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-kinesis", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": s["arn"]}]}))

    # --- two configs: both accepted ---------------------------------------------------------------
    for side, s in sides.items():
        cfg = cf.create_realtime_log_config(
            Name=ctx.unique_name(f"sim2real-obs3-rtl-{side}-"), SamplingRate=100, Fields=FIELDS,
            EndPoints=[{"StreamType": "Kinesis",
                        "KinesisStreamConfig": {"RoleARN": s["role_arn"], "StreamARN": s["arn"]}}],
        )["RealtimeLogConfig"]
        ctx.on_cleanup(lambda a=cfg["ARN"]: _delete_rtl_if_present(cf, a))
        s["config_arn"] = cfg["ARN"]
        s["index"] = {f: i for i, f in enumerate(cfg["Fields"])}
        assert set(cfg["Fields"]) == set(FIELDS), f"config must keep the field set {FIELDS}, got {cfg['Fields']}"
    broken_read = cf.get_realtime_log_config(ARN=sides["broken"]["config_arn"])["RealtimeLogConfig"]
    assert broken_read["EndPoints"][0]["KinesisStreamConfig"]["RoleARN"] == sides["broken"]["role_arn"], (
        f"the broken config must be stored as created, with the role lacking PutRecord, got {broken_read!r}")

    # --- origin + one distribution, one cache behaviour per config --------------------------------
    bucket = ctx.unique_name("sim2real-obs3-rtl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    stem = ctx.unique_name("obj-")
    paths = {"control": f"/{stem}.txt", "broken": f"/broken/{stem}.txt"}
    for p in paths.values():
        s3.put_object(Bucket=bucket, Key=p[1:], Body=b"sim2real-obs-cloudfront-3-rtl", ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-obs3-rtl-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always", "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac_if_present(cf, oac_id))

    behaviour = {"TargetOriginId": "s3", "ViewerProtocolPolicy": "allow-all",
                 "CachePolicyId": MANAGED_CACHING_DISABLED}
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-obs3-rtl-"),
        "Comment": "sim2real obs-cloudfront-3 real-time log permission negative",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3", "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {**behaviour, "RealtimeLogConfigArn": sides["control"]["config_arn"]},
        "CacheBehaviors": {"Quantity": 1, "Items": [{
            **behaviour, "PathPattern": "broken/*",
            "RealtimeLogConfigArn": sides["broken"]["config_arn"]}]},
    })["Distribution"]
    dist_id, domain = dist["Id"], dist["DomainName"]
    # After the configs' cleanup, so LIFO deletes the distribution first (a referenced config
    # cannot be deleted).
    ctx.on_cleanup(lambda: _release_distribution(cf, dist_id))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAGS})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                       "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
                       "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}}}],
    }))
    attached = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["CacheBehaviors"]["Items"][0]
    assert attached["RealtimeLogConfigArn"] == sides["broken"]["config_arn"], (
        f"attaching the broken config must be accepted and stored, got {attached.get('RealtimeLogConfigArn')!r}")

    _wait_deployed(cf, dist_id)
    readers = {side: _Reader(kinesis, s["stream"]) for side, s in sides.items()}

    # --- the window: interleaved requests, both streams polled until the control has them all,
    # then the broken stream is held empty for 3x the latency the control took -----------------
    # Interleaving makes the control the barrier; records join requests on x-edge-request-id.
    sent = {"control": [], "broken": []}
    start = time.monotonic()
    for _ in range(_ROUNDS):
        for side in ("control", "broken"):
            sent[side].append(_served(ctx, f"{domain}{paths[side]}"))
    control = readers["control"]
    ix = sides["control"]["index"]

    def _control_missing() -> list[str]:
        for r in readers.values():
            r.drain()
        seen = {ln.split("\t")[ix["x-edge-request-id"]] for ln in control.lines}
        return [rid for rid in sent["control"] if rid not in seen]

    while _control_missing() and time.monotonic() - start < WINDOW_S:
        time.sleep(2.0)
    hold_until = time.monotonic() + max(_ABSENCE_FLOOR_S, 3.0 * (time.monotonic() - start))
    while time.monotonic() < hold_until and readers["broken"].records == 0:
        time.sleep(2.0)
        _control_missing()

    by_rid = {ln.split("\t")[ix["x-edge-request-id"]]: ln.split("\t") for ln in control.lines}
    missing = [rid for rid in sent["control"] if rid not in by_rid]
    assert len(sent["control"]) >= 3 and not missing, (
        f"the control config must deliver every one of its {len(sent['control'])} requests within "
        f"{WINDOW_S:.0f}s; missing {missing} (control lines: {control.lines!r})")
    for rid in sent["control"]:
        row = by_rid[rid]
        assert (row[ix["cs-uri-stem"]], row[ix["sc-status"]]) == (paths["control"], "200"), (
            f"control record {rid} must describe {paths['control']} -> 200, got {row!r}")
    routed_wrong = [ln for ln in control.lines if paths["broken"] in ln]
    assert not routed_wrong, (
        f"requests to broken/* must not be logged through the default behaviour's config: {routed_wrong!r}")
    assert readers["broken"].records == 0, (
        f"a real-time log config whose role lacks {_PUT} must deliver nothing, but GetRecords on "
        f"{sides['broken']['stream']} returned {readers['broken'].records} records: {readers['broken'].lines!r}")

    # --- close the loop: grant the one missing permission; the same stream starts receiving -----
    broken = sides["broken"]
    iam.put_role_policy(RoleName=broken["role"], PolicyName="sim2real-kinesis", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": _DESCRIBE + _PUT, "Resource": broken["arn"]}]}))
    bix = broken["index"]
    repaired: list[str] = []

    def probe():
        repaired.append(_served(ctx, f"{domain}{paths['broken']}"))
        lines = readers["broken"].drain().lines
        return {ln.split("\t")[bix["x-edge-request-id"]] for ln in lines} & set(repaired)

    _poll_until(probe, bool, timeout_s=900.0, interval_s=20.0,
                description=f"a record in {broken['stream']} once its role was granted {_PUT}")
    rows = [ln.split("\t") for ln in readers["broken"].lines]
    assert all(r[bix["cs-uri-stem"]] == paths["broken"] for r in rows), (
        f"the repaired stream must carry only broken/* requests, got {readers['broken'].lines!r}")

    # --- teardown of the slow chain, in the body (see _teardown_distributions) -----------------
    _teardown_distributions(cf, [dist_id])
    for s in sides.values():
        _retry_in_use(lambda a=s["config_arn"]: cf.delete_realtime_log_config(ARN=a))
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
