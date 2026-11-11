"""cw-metric-stream-zero-buffer-firehose-delivers-while-untrusted-role-delivers-nothing."""
from __future__ import annotations

import gzip
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cw-metric-stream-zero-buffer-firehose-delivers-while-untrusted-role-delivers-nothing"
GROUP = "metric-streams-delivery"
SERVICES = ["cloudwatch", "firehose", "s3"]

_NAMESPACE_VALUE = 777.0
_METRIC_NAME = "StreamedMetric"
_GOOD_PREFIX = "sim2real-depth-good/"
_BROKEN_PREFIX = "sim2real-depth-broken/"
_TRUSTED = "streams.metrics.cloudwatch.amazonaws.com"
_UNTRUSTED = "ec2.amazonaws.com"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Metric-Streams.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A metric stream exports the published datapoint through a zero-buffer Firehose stream to S3,
    while a twin stream whose role trusts ec2 instead delivers nothing until it is given the
    trusted role.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/create-configure-backup.html
    """
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _bucket(ctx)
    good_fh = _delivery_stream(ctx, bucket, _GOOD_PREFIX, "good")
    broken_fh = _delivery_stream(ctx, bucket, _BROKEN_PREFIX, "broken")
    _await_active(ctx, [good_fh, broken_fh])

    namespace = ctx.unique_name("Sim2RealDepthStreamNs")
    good_role = _stream_role(ctx, [good_fh["arn"], broken_fh["arn"]], _TRUSTED, "good")
    broken_role = _stream_role(ctx, [good_fh["arn"], broken_fh["arn"]], _UNTRUSTED, "broken")

    # PutMetricStream does not validate the role's trust policy, so the broken stream is accepted
    # and fails silently; the negative is a delivery differential, not an error code.
    good_stream = _metric_stream(ctx, namespace, good_fh["arn"], good_role, "gms")
    broken_stream = _metric_stream(ctx, namespace, broken_fh["arn"], broken_role, "bms")

    for name, arn in ((good_stream, good_fh["arn"]), (broken_stream, broken_fh["arn"])):
        described = cw.get_metric_stream(Name=name)
        assert described["State"] == "running", (
            f"metric stream {name!r} is in state {described['State']!r}, expected 'running'; "
            f"nothing below would export"
        )
        assert described["FirehoseArn"] == arn, (
            f"metric stream {name!r} targets {described['FirehoseArn']!r}, expected {arn!r}"
        )

    # One publisher feeding BOTH streams, so the two sides see the identical series.
    published_at = _publish(cw, namespace)

    # Barrier: the good prefix must deliver, and deliver more than once (one arrival can be luck).
    good_keys = _poll_objects(
        s3, bucket, _GOOD_PREFIX,
        predicate=lambda keys: len(keys) >= 2,
        timeout_s=600.0,
        republish=lambda: _publish(cw, namespace),
        description=(
            f"the metric stream exported at least two objects to s3://{bucket}/{_GOOD_PREFIX}"
        ),
    )
    assert len(good_keys) >= 2, f"{good_keys!r}"

    records = _records(s3, bucket, good_keys)
    assert records, (
        f"Firehose wrote {len(good_keys)} object(s) to the good prefix but they held no parsable "
        f"newline-delimited JSON records: keys {good_keys!r}"
    )
    mine = [r for r in records if r.get("namespace") == namespace]
    assert mine, (
        f"no delivered record carries the streamed namespace {namespace!r}; delivered namespaces "
        f"were {sorted({r.get('namespace') for r in records})!r}"
    )
    assert any(r.get("metric_name") == _METRIC_NAME for r in mine), (
        f"no delivered record carries metric name {_METRIC_NAME!r}; got "
        f"{sorted({r.get('metric_name') for r in mine})!r}"
    )
    rec = next(r for r in mine if r.get("metric_name") == _METRIC_NAME)
    assert rec["value"]["max"] == _NAMESPACE_VALUE, (
        f"the exported datapoint's value is {rec['value']!r}, expected max == "
        f"{_NAMESPACE_VALUE!r} -- the payload is not the data that was published"
    )
    assert rec["value"]["min"] == _NAMESPACE_VALUE, f"{rec['value']!r}"
    assert rec["unit"] == "None", (
        f"the exported unit is {rec['unit']!r}; PutMetricData supplied no Unit, which CloudWatch "
        f"streams as the literal string 'None'"
    )
    assert rec["account_id"] == account_id, (
        f"the exported record claims account {rec['account_id']!r}, expected {account_id!r}"
    )
    assert rec["region"] == ctx.region, (
        f"the exported record claims region {rec['region']!r}, expected {ctx.region!r}"
    )
    assert rec["metric_stream_name"] == good_stream, (
        f"the exported record names stream {rec['metric_stream_name']!r}, expected {good_stream!r}"
    )
    assert rec["timestamp"] >= int(published_at.timestamp() * 1000) - 300_000, (
        f"the exported timestamp {rec['timestamp']!r} predates the publish window starting "
        f"{published_at.isoformat()}"
    )

    # The good side has sustained delivery. Only now assert the absence on the broken side.
    broken_keys = _list_objects(s3, bucket, _BROKEN_PREFIX)
    assert broken_keys == [], (
        f"the metric stream whose role trusts {_UNTRUSTED!r} still exported "
        f"{len(broken_keys)} object(s) to s3://{bucket}/{_BROKEN_PREFIX}: {broken_keys!r}. "
        f"CloudWatch cannot assume that role, so nothing may be delivered through it"
    )

    # Repair EXACTLY the one broken thing and require the same prefix to receive.
    cw.put_metric_stream(
        Name=broken_stream,
        FirehoseArn=broken_fh["arn"],
        RoleArn=good_role,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": namespace}],
    )
    repaired = cw.get_metric_stream(Name=broken_stream)
    assert repaired["RoleArn"] == good_role, (
        f"the repair did not take: stream {broken_stream!r} still carries RoleArn "
        f"{repaired['RoleArn']!r}"
    )
    assert repaired["FirehoseArn"] == broken_fh["arn"], (
        f"the repair changed the target as well as the role: {repaired['FirehoseArn']!r}"
    )

    repaired_keys = _poll_objects(
        s3, bucket, _BROKEN_PREFIX,
        predicate=lambda keys: len(keys) >= 1,
        timeout_s=600.0,
        republish=lambda: _publish(cw, namespace),
        description=(
            f"the repaired stream exported to s3://{bucket}/{_BROKEN_PREFIX}, proving the prefix "
            f"and its Firehose stream were reachable all along and only the trust policy "
            f"suppressed delivery"
        ),
    )
    assert repaired_keys, f"{repaired_keys!r}"
    repaired_records = [
        r for r in _records(s3, bucket, repaired_keys) if r.get("namespace") == namespace
    ]
    assert repaired_records, (
        f"the repaired prefix received {len(repaired_keys)} object(s) but none carried namespace "
        f"{namespace!r}: {repaired_keys!r}"
    )
    assert all(r["metric_stream_name"] == broken_stream for r in repaired_records), (
        f"the repaired prefix received records from another stream: "
        f"{sorted({r['metric_stream_name'] for r in repaired_records})!r}"
    )


def _publish(cw, namespace):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": _METRIC_NAME, "Timestamp": now, "Value": _NAMESPACE_VALUE}],
    )
    return now


def _bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-depth-mstream-")
    kw: dict = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        stale = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if stale:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": stale}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        stale = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if stale:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": stale}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _role(ctx, label, trust_service, policy_doc) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-depth-{label}-role-")
    arn = iam.create_role(
        RoleName=name,
        Description="sim2real-depth cloudwatch metric stream export",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trust_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "cloudwatch-metric-stream-depth"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=name)))
    iam.put_role_policy(
        RoleName=name, PolicyName="sim2real-depth-inline", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-depth-inline")
        )
    )
    # IAM exposes no condition reporting that a role has become effective, so correctness rests
    # entirely on the bounded AccessDenied retry at first USE (_retry, below) rather than a sleep here.
    return arn


def _stream_role(ctx, firehose_arns, trusted_service, label) -> str:
    return _role(
        ctx,
        f"ms{label}",
        trusted_service,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": list(firehose_arns),
                }
            ],
        },
    )


def _delivery_stream(ctx, bucket, prefix, label) -> dict:
    firehose = ctx.client("firehose")
    role_arn = _role(
        ctx,
        f"fh{label}",
        "firehose.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
    )
    name = ctx.unique_name(f"sim2real-depth-fh{label}-")
    _retry(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket}",
                "Prefix": prefix,
                "ErrorOutputPrefix": f"{prefix}errors/",
                # A zero buffering interval delivers within seconds of each metric stream send.
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
                "CompressionFormat": "UNCOMPRESSED",
            },
            Tags=[{"Key": "sim2real", "Value": "cloudwatch-metric-stream-depth"}],
        ),
        attempts=12,
        interval_s=5.0,
    )
    ctx.on_cleanup(
        lambda: _teardown(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    )
    return {"name": name, "arn": _arn_of(firehose, name), "prefix": prefix}


def _arn_of(firehose, name) -> str:
    return firehose.describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamARN"]


def _await_active(ctx, streams) -> None:
    """Poll both delivery streams to ACTIVE in parallel, so their waits overlap rather than sum."""
    firehose = ctx.client("firehose")

    def _one(stream):
        deadline = time.monotonic() + 300.0
        while True:
            status = firehose.describe_delivery_stream(DeliveryStreamName=stream["name"])[
                "DeliveryStreamDescription"
            ]["DeliveryStreamStatus"]
            if status == "ACTIVE":
                return status
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"delivery stream {stream['name']!r} stalled in {status!r} after 300s"
                )
            time.sleep(5.0)

    with ThreadPoolExecutor(max_workers=len(streams)) as pool:
        for status in pool.map(_one, streams):
            assert status == "ACTIVE", f"{status!r}"


def _metric_stream(ctx, namespace, firehose_arn, role_arn, label) -> str:
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name(f"sim2real-depth-{label}-")
    # Registered BEFORE the call: PutMetricStream is an upsert with no synchronous validation,
    # so the stream may exist even if a later step fails.
    ctx.on_cleanup(lambda: _teardown(lambda: cw.delete_metric_stream(Name=name)))
    ctx.on_cleanup(lambda: _teardown(lambda: cw.stop_metric_streams(Names=[name])))
    _retry(
        lambda: cw.put_metric_stream(
            Name=name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": namespace}],
        ),
        attempts=12,
        interval_s=5.0,
    )
    return name


def _list_objects(s3, bucket, prefix) -> list[str]:
    """Every key under prefix, paginated, excluding Firehose's <prefix>errors/ failure output."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["Key"].startswith(f"{prefix}errors/"):
                continue
            keys.append(obj["Key"])
    return sorted(keys)


def _poll_objects(s3, bucket, prefix, *, predicate, timeout_s, republish, description):
    """Poll S3 until predicate(keys); FAIL on exhaustion, never skip.

    Republishes each round: a metric stream exports only what is being written, so a single seed
    can leave the exporter with nothing to send.
    """
    deadline = time.monotonic() + timeout_s
    keys = []
    while True:
        keys = _list_objects(s3, bucket, prefix)
        if predicate(keys):
            return keys
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last listing {keys!r}"
            )
        republish()
        time.sleep(5.0)


def _records(s3, bucket, keys) -> list[dict]:
    """Every newline-delimited JSON record in the delivered objects, gunzipped if needed."""
    out = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        for line in body.decode("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                # A single object can hold several concatenated JSON documents with no separator,
                # which is why raw_decode is used rather than treating the line as one document.
                out.extend(_split_json(line))
    return out


def _split_json(blob) -> list[dict]:
    decoder = json.JSONDecoder()
    out, idx = [], 0
    while idx < len(blob):
        try:
            obj, end = decoder.raw_decode(blob, idx)
        except ValueError:
            return out
        out.append(obj)
        idx = end
        while idx < len(blob) and blob[idx] in " \r\n\t":
            idx += 1
    return out


def _retry(fn, *, attempts, interval_s):
    """Call fn(), retrying the bounded IAM-propagation window at first use of a new role."""
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            message = (err.get("Message") or "").lower()
            transient = code in (
                "AccessDenied", "AccessDeniedException", "ValidationException",
                "InvalidArgumentException",
            ) and ("assume" in message or "not authorized" in message or "trust" in message
                   or "iam" in message or "role" in message)
            if not transient or i == attempts - 1:
                raise
            time.sleep(interval_s)
    raise AssertionError("unreachable")


def _teardown(fn) -> None:
    """Run one teardown call: return when the resource is already gone, retry while it is still in use."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NoSuchEntity", "ResourceNotFoundException", "ResourceNotFound"):
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
