"""xsvc-cloudfront-3-realtime-log-role-denied-putrecord-delivers-nothing."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-3-realtime-log-role-denied-putrecord-delivers-nothing"
GROUP = "data-plane"
SERVICES = ["cloudfront", "kinesis"]

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
#: Managed CachingDisabled: every viewer request reaches the origin and is logged as a Miss.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_FIELDS = ["timestamp", "c-ip", "cs-uri-stem", "sc-status", "x-edge-response-result-type"]
_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]
_GOOD_REQUESTS = 3


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout - never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=10.0) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_wait(cf, dist_id) -> str:
    """Disable the distribution and wait for that change to deploy; return the ETag to delete with.
    Called at the END of the check body: the engine bounds the whole cleanup chain at 60 s, and a
    disable round trip takes minutes, so the slow half of teardown cannot live in a cleanup."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    return _wait_distribution_deployed(cf, dist_id)


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Cleanup: delete at once if the body already disabled it; otherwise disable and give the
    change a bounded window, then report the leak."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        r = cf.get_distribution(Id=dist_id)
        if r["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=r["ETag"])
            return
        time.sleep(5)
    raise RuntimeError(
        f"cloudfront distribution {dist_id} still deploying its disable; not deleted"
    )


def _retry_in_use(fn, *, timeout_s=20.0) -> None:
    """A resource a just-deleted distribution referenced can stay in-use for a few seconds."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # botocore ClientError
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if "InUse" not in code or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _create_bucket(ctx, s3, bucket) -> None:
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


def _fetch_ok(session, url, *, timeout_s=240.0, interval_s=5.0):
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


class _Stream:
    """A one-shard stream this check owns, read from TRIM_HORIZON so nothing predates it."""

    def __init__(self, ctx, kinesis, label):
        self.kinesis = kinesis
        self.name = ctx.unique_name(f"sim2real-xsvc-cfrtl-{label}-")
        kinesis.create_stream(StreamName=self.name, ShardCount=1)
        ctx.on_cleanup(lambda: ctx.client("kinesis").delete_stream(
            StreamName=self.name, EnforceConsumerDeletion=True))
        self.arn = _poll_until(
            lambda: kinesis.describe_stream_summary(
                StreamName=self.name)["StreamDescriptionSummary"],
            lambda s: s["StreamStatus"] == "ACTIVE", timeout_s=300.0, interval_s=5.0,
            description=f"kinesis stream {self.name} to become ACTIVE")["StreamARN"]
        kinesis.add_tags_to_stream(StreamName=self.name,
                                   Tags={t["Key"]: t["Value"] for t in _TAG_SET})
        self.lines: list[str] = []
        self.it = None

    def open(self):
        shard = self.kinesis.describe_stream(
            StreamName=self.name)["StreamDescription"]["Shards"][0]["ShardId"]
        self.it = self.kinesis.get_shard_iterator(
            StreamName=self.name, ShardId=shard, ShardIteratorType="TRIM_HORIZON")["ShardIterator"]

    def drain(self) -> list[str]:
        resp = self.kinesis.get_records(ShardIterator=self.it, Limit=1000)
        self.it = resp["NextShardIterator"]
        for record in resp["Records"]:
            self.lines.extend(ln for ln in record["Data"].decode("utf-8").splitlines() if ln)
        return self.lines


@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A real-time log config whose role lacks kinesis:PutRecord(s) delivers zero records, while a
    sibling config with a permitted role delivers one record per request in its Fields order;
    repointing the denied config at the permitted role makes its stream receive.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    good = _Stream(ctx, kinesis, "ok")
    bad = _Stream(ctx, kinesis, "no")

    trust = json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
        "Action": "sts:AssumeRole"}]})
    policy_name = "sim2real-kinesis"

    def role(label, actions, streams):
        name = ctx.unique_name(f"sim2real-xsvc-cfrtl-{label}-")
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust,
                              Description="sim2real CloudFront real-time log delivery",
                              Tags=_TAG_SET)["Role"]["Arn"]
        ctx.on_cleanup(lambda: _delete_role(ctx.client("iam"), name, policy_name))
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": streams}]}))
        return arn

    describe = ["kinesis:DescribeStreamSummary", "kinesis:DescribeStream"]
    put = ["kinesis:PutRecord", "kinesis:PutRecords"]
    # The permitted role may write to BOTH streams, so the repair step below changes one thing.
    good_role = role("ok", describe + put, [good.arn, bad.arn])
    denied_role = role("no", describe, [bad.arn])

    def config(label, role_arn, stream_arn):
        c = cf.create_realtime_log_config(
            Name=ctx.unique_name(f"sim2real-xsvc-cfrtl-{label}-"), SamplingRate=100,
            Fields=_FIELDS,
            EndPoints=[{"StreamType": "Kinesis",
                        "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn}}],
        )["RealtimeLogConfig"]
        ctx.on_cleanup(lambda: _retry_in_use(
            lambda: ctx.client("cloudfront").delete_realtime_log_config(ARN=c["ARN"])))
        return c

    good_cfg = config("ok", good_role, good.arn)
    bad_cfg = config("no", denied_role, bad.arn)
    # Field order is CloudFront's own canonical order, read from its own GET response - never the
    # order requested and never a hardcoded guess.
    fields = cf.get_realtime_log_config(ARN=good_cfg["ARN"])["RealtimeLogConfig"]["Fields"]
    assert sorted(fields) == sorted(_FIELDS), (
        f"GetRealtimeLogConfig must return the configured field set {sorted(_FIELDS)!r}, got "
        f"{fields!r}"
    )
    idx = {name: i for i, name in enumerate(fields)}

    bucket = ctx.unique_name("sim2real-xsvc-cfrtl-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    tok = ctx.unique_name("k")
    good_keys = [f"ok/{tok}-{i}.txt" for i in range(_GOOD_REQUESTS)]
    bad_key = f"no/{tok}.txt"
    repaired_key = f"no/{tok}-repaired.txt"
    for key in good_keys + [bad_key, repaired_key]:
        s3.put_object(Bucket=bucket, Key=key, Body=key.encode(), ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cfrtl-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always",
        "SigningProtocol": "sigv4"})["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _retry_in_use(lambda: _delete_with_etag(
        cf.get_origin_access_control, cf.delete_origin_access_control, oac_id)))

    origin = "s3origin"
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-xsvc-cfrtl-cr-"),
        "Comment": "sim2real real-time log role denial",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": origin, "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": oac_id}]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin, "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED, "RealtimeLogConfigArn": good_cfg["ARN"]},
        "CacheBehaviors": {"Quantity": 1, "Items": [{
            "PathPattern": "/no/*", "TargetOriginId": origin, "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED, "RealtimeLogConfigArn": bad_cfg["ARN"]}]},
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered after the configs' cleanups so LIFO deletes the distribution first.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx.client("cloudfront"), dist_id))
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}}}]}))
    _wait_distribution_deployed(cf, dist_id)

    good.open()
    bad.open()
    session = requests.Session()
    base, route_headers = ctx.endpoint_route(dist["DomainName"])
    session.headers.update(route_headers)
    # The denied behaviour is requested FIRST, so every good-side record below postdates it; the
    # denied stream is asserted empty only after every good-side request has been delivered.
    served = _fetch_ok(session, f"{base}/{bad_key}")
    assert served.content == bad_key.encode(), (
        f"the edge served the wrong bytes for /{bad_key}: {served.content[:120]!r}"
    )
    for key in good_keys:
        r = _fetch_ok(session, f"{base}/{key}")
        assert r.content == key.encode(), f"the edge served the wrong bytes for /{key}: {r.content[:120]!r}"

    def good_matches():
        lines = good.drain()
        return {k: [ln for ln in lines if f"/{k}\t" in ln + "\t"] for k in good_keys}

    _poll_until(good_matches, lambda m: all(m.values()), timeout_s=420.0, interval_s=5.0,
                description=f"a record for each of {good_keys!r} in {good.name}")
    # A sentinel request is a further good-side delivery: once it lands, any duplicate of the
    # earlier records and any record the denied side was going to deliver has had a full extra
    # trip to arrive.
    sentinel = good_keys[0]
    _fetch_ok(session, f"{base}/{sentinel}")
    _poll_until(lambda: (bad.drain(), good_matches())[1], lambda m: len(m[sentinel]) >= 2,
                timeout_s=420.0, interval_s=5.0,
                description=f"the sentinel second request for /{sentinel} to reach {good.name}")
    got = good_matches()
    assert len(got[sentinel]) == 2, (
        f"two viewer requests for /{sentinel} must produce exactly two records, got "
        f"{got[sentinel]!r}"
    )
    got[sentinel] = got[sentinel][:1]
    for key in good_keys:
        assert len(got[key]) == 1, (
            f"one viewer request must produce exactly one real-time log record for /{key}, got "
            f"{got[key]!r}"
        )
        parts = got[key][0].split("\t")
        assert len(parts) == len(fields), (
            f"a record must carry exactly the {len(fields)} configured fields, got {parts!r}"
        )
        assert parts[idx["cs-uri-stem"]] == f"/{key}", (
            f"cs-uri-stem sits at index {idx['cs-uri-stem']} of the config's own Fields "
            f"{fields!r}; got {parts!r}"
        )
        assert parts[idx["sc-status"]] == "200", (
            f"sc-status sits at index {idx['sc-status']} of {fields!r}; got {parts!r}"
        )
        assert parts[idx["x-edge-response-result-type"]] == "Miss", (
            f"x-edge-response-result-type sits at index {idx['x-edge-response-result-type']} of "
            f"{fields!r} and caching is disabled; got {parts!r}"
        )
    stray = [ln for ln in good.lines if "/no/" in ln]
    assert stray == [], f"the /no/* behaviour must not log to the default config's stream: {stray!r}"
    assert bad.lines == [], (
        f"a config whose role lacks kinesis:PutRecord/PutRecords must deliver nothing, but stream "
        f"{bad.name} received {bad.lines!r}"
    )

    # Repair the one broken thing: point the denied config at the permitted role.
    cur = cf.get_realtime_log_config(ARN=bad_cfg["ARN"])["RealtimeLogConfig"]
    cf.update_realtime_log_config(
        ARN=bad_cfg["ARN"], SamplingRate=cur["SamplingRate"], Fields=cur["Fields"],
        EndPoints=[{"StreamType": "Kinesis",
                    "KinesisStreamConfig": {"RoleARN": good_role, "StreamARN": bad.arn}}])

    def repaired():
        _fetch_ok(session, f"{base}/{repaired_key}")
        return [ln for ln in bad.drain() if f"/{repaired_key}\t" in ln + "\t"]

    _poll_until(repaired, lambda v: len(v) >= 1, timeout_s=600.0, interval_s=15.0,
                description=f"stream {bad.name} to receive /{repaired_key} after the config was "
                            f"repointed at the permitted role")
    assert not [ln for ln in bad.lines if f"/{bad_key}\t" in ln + "\t"], (
        f"the request served while the role was denied must never be delivered later: "
        f"{bad.lines!r}"
    )

    # Teardown's slow half, in the body (the engine bounds cleanup at 60 s): the disable must
    # deploy before the distribution, and then its configs and OAC, can be deleted.
    _disable_and_wait(cf, dist_id)
    assert cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["Enabled"] is False, (
        f"distribution {dist_id} must read back disabled after the disable deployed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
