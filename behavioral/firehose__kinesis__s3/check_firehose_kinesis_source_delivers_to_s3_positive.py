"""firehose-kinesis-source-delivers-to-s3-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-kinesis-source-delivers-to-s3-positive"
GROUP = "event-propagation"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Records put onto a Kinesis stream configured as a Firehose source land as objects in S3."""
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")
    firehose = ctx.client("firehose")

    bucket, bucket_arn = _create_bucket(ctx)
    stream_name, stream_arn = _create_kinesis_stream(ctx)
    role_arn, role_name = _create_role(
        ctx,
        [_kinesis_read_statement(stream_arn), _s3_write_statement(bucket_arn)],
        "del",
    )

    delivery_name = ctx.unique_name("sim2real-fh-")
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        delivery_name,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": stream_arn, "RoleARN": role_arn},
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    _wait_delivery_stream_active(firehose, delivery_name)

    marker = ctx.unique_name("marker-")
    kinesis.put_record(
        StreamName=stream_name, Data=f"sim2real-payload-{marker}".encode(), PartitionKey="pk-1"
    )

    objects = _poll_until(
        lambda: _list_objects(s3, bucket),
        lambda objs: len(objs) >= 1,
        timeout_s=240,
        interval_s=10,
    )
    assert len(objects) >= 1, f"expected firehose to deliver at least one object to {bucket}, found none"

    found = False
    for obj in objects:
        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        if marker.encode() in body:
            found = True
            break
    assert found, "delivered S3 object did not contain the Kinesis record payload"
    # Tear down in reverse dependency order and prove each resource gone.
    account = stream_arn.split(":")[4]
    _gone_delivery_stream(ctx, delivery_name, account)
    _gone_stream(ctx, stream_name, account)
    _gone_role(ctx, role_name)
    _gone_bucket(ctx, bucket)


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is CreateBucket's own implicit default: passing a LocationConstraint for it is
    # itself rejected, so this is an API quirk, not a region pin.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        token = None
        while True:
            kw: dict[str, Any] = {"Bucket": name}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_tolerant(_cleanup, "NoSuchBucket"))
    return name, f"arn:aws:s3:::{name}"


def _create_kinesis_stream(ctx) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-fh-stream-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(
        _tolerant(
            lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True),
            "ResourceNotFoundException",
        )
    )
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _kinesis_read_statement(stream_arn: str) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": [
            "kinesis:DescribeStream",
            "kinesis:DescribeStreamSummary",
            "kinesis:GetRecords",
            "kinesis:GetShardIterator",
            "kinesis:ListShards",
        ],
        "Resource": stream_arn,
    }


def _s3_write_statement(bucket_arn: str) -> dict[str, Any]:
    resource = "*" if bucket_arn == "*" else [bucket_arn, f"{bucket_arn}/*"]
    return {
        "Effect": "Allow",
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        ],
        "Resource": resource,
    }


def _create_role(ctx, statements: list[dict[str, Any]], suffix: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_name = ctx.unique_name(f"sim2real-fh-role-{suffix}-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_tolerant(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity", "NoSuchEntityException"))
    policy_name = "delivery-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        _tolerant(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name),
            "NoSuchEntity", "NoSuchEntityException",
        )
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"], role_name


def _create_delivery_stream_with_retry(ctx, firehose, name: str, **kwargs: Any) -> None:
    deadline = time.monotonic() + 150
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(
        _tolerant(
            lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
            "ResourceNotFoundException",
        )
    )


def _wait_delivery_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=timeout_s,
        interval_s=5,
    )
    if status != "ACTIVE":
        raise AssertionError(f"delivery stream {name} failed to activate: {status}")


def _list_objects(s3, bucket: str, prefix: str = "") -> list[dict[str, Any]]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str, expected: str) -> None:
    """``fn()`` must fail with one of ``codes`` at ``status`` and exactly the ``expected`` message."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        assert code in codes and got == status, (
            f"{what}: expected {'/'.join(codes)} HTTP {status}, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg == expected, f"{what}: {code} message {msg[:200]!r}, expected {expected!r}"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, expected, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what, expected)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def _gone_role(ctx, name: str, path: str = "/") -> None:
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=p)
    iam.delete_role(RoleName=name)
    nf = ("NoSuchEntity",)
    gone = f"The role with name {name} cannot be found."
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}", gone)
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles", PathPrefix=path)}
    assert name not in listed, f"ListRoles still lists deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}", gone,
    )


def _gone_stream(ctx, name: str, account: str) -> None:
    kin = ctx.client("kinesis")
    kin.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    nf = ("ResourceNotFoundException",)
    gone = f"Stream {name} under account {account} not found."
    _poll_refused(lambda: kin.describe_stream_summary(StreamName=name), nf, 400, f"DescribeStreamSummary {name}", gone)
    assert name not in _paged(kin, "list_streams", "StreamNames"), f"ListStreams still lists deleted stream {name}"
    _refused(lambda: kin.put_record(StreamName=name, Data=b"x", PartitionKey="k"), nf, 400, f"PutRecord {name}", gone)


def _empty_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})


def _gone_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    _empty_bucket(s3, bucket)
    s3.delete_bucket(Bucket=bucket)
    # HeadBucket has no body: the code is the bare status.
    _poll_refused(lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket", "NotFound"), 404, f"HeadBucket {bucket}",
                  "Not Found")
    names = {b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])}
    assert bucket not in names, f"ListBuckets still lists deleted bucket {bucket}"
    _refused(lambda: s3.put_object(Bucket=bucket, Key="gone", Body=b"x"), ("NoSuchBucket",), 404, f"PutObject {bucket}",
             "The specified bucket does not exist")


# ---- Firehose delivery stream: DescribeDeliveryStream / ListDeliveryStreams / PutRecord ----------
def _gone_delivery_stream(ctx, name: str, account: str) -> None:
    fh = ctx.client("firehose")
    fh.delete_delivery_stream(DeliveryStreamName=name)
    nf = ("ResourceNotFoundException",)
    # DELETING is not terminal: poll to the not-found answer.
    _poll_refused(
        lambda: fh.describe_delivery_stream(DeliveryStreamName=name), nf, 400,
        f"DescribeDeliveryStream {name}", f"Firehose under account {account} not found.",
    )
    listed: list[str] = []
    kw: dict[str, Any] = {"Limit": 10000}
    while True:
        page = fh.list_delivery_streams(**kw)
        listed.extend(page.get("DeliveryStreamNames", []))
        if not page.get("HasMoreDeliveryStreams") or not page.get("DeliveryStreamNames"):
            break
        kw["ExclusiveStartDeliveryStreamName"] = page["DeliveryStreamNames"][-1]
    assert name not in listed, f"ListDeliveryStreams still lists deleted delivery stream {name}"
    _refused(
        lambda: fh.put_record(DeliveryStreamName=name, Record={"Data": b"gone"}),
        nf, 400, f"PutRecord {name}", f"Firehose not found under account {account}.",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
