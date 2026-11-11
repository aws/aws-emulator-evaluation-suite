"""kinesis-esm-s3-on-failure-destination-writes-the-full-invocation-record."""
from __future__ import annotations

import base64
import json
import re
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-s3-on-failure-destination-writes-the-full-invocation-record"
GROUP = "error-propagation"
SERVICES = ["kinesis", "lambda", "s3"]

_EFFECT_BUDGET_S = 200
_KEY_RE = re.compile(
    r"^aws/lambda/[0-9a-f-]{36}/shardId-\d{12}/\d{4}/\d{2}/\d{2}/"
    r"\d{4}-\d{2}-\d{2}T\d{2}\.\d{2}\.\d{2}-[0-9a-f-]{36}$"
)


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Kinesis ESM whose OnFailure destination names an S3 bucket writes one object per
    exhausted batch, keyed `aws/lambda/<ESM-UUID>/<shardId>/<date>/<timestamp>-<uuid>`, carrying
    the same KinesisBatchInfo pointer SQS/SNS get PLUS the entire original invocation payload.
    """
    kinesis = ctx.client("kinesis")
    s3 = ctx.client("s3")

    stream = _create_stream(ctx)
    bucket = _create_bucket(ctx)

    code = """
    def handler(event, context):
        raise RuntimeError("deliberate-failure")
    """
    fn = _create_lambda(
        ctx, code,
        statements=[
            {"Action": ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream",
                        "kinesis:DescribeStreamSummary", "kinesis:ListShards"],
             "Resource": stream["arn"]},
            {"Action": ["s3:PutObject", "s3:ListBucket"],
             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
        ],
    )

    payload = {"marker": ctx.unique_name("sim2real-payload-")}
    put = kinesis.put_record(StreamName=stream["name"], PartitionKey="k",
                             Data=json.dumps(payload).encode())
    seq = put["SequenceNumber"]
    shard_id = put["ShardId"]

    esm_uuid = _create_esm(
        ctx, fn["name"], stream["arn"], StartingPosition="TRIM_HORIZON", BatchSize=1,
        MaximumBatchingWindowInSeconds=0, MaximumRetryAttempts=0,
        DestinationConfig={"OnFailure": {"Destination": f"arn:aws:s3:::{bucket}"}},
    )

    expected_prefix = f"aws/lambda/{esm_uuid}/"
    objs = _poll_until(
        ctx, lambda: s3.list_objects_v2(Bucket=bucket, Prefix=expected_prefix).get("Contents", []),
        lambda found: len(found) >= 1, timeout_s=_EFFECT_BUDGET_S, interval_s=5.0,
        description="an OnFailure object under the ESM's S3 prefix",
    )
    assert len(objs) == 1, f"one exhausted batch must yield one S3 object, got {objs!r}"
    key = objs[0]["Key"]
    assert _KEY_RE.match(key), (
        f"key {key!r} does not match aws/lambda/<ESM-UUID>/<shardId>/YYYY/MM/DD/"
        f"YYYY-MM-DDTHH.MM.SS-<uuid>"
    )
    assert key.startswith(f"aws/lambda/{esm_uuid}/{shard_id}/"), (
        f"key {key!r} must be scoped to this mapping's UUID and shard {shard_id!r}"
    )

    body = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())

    # --- the pointer, field by field, same shape SQS/SNS destinations carry ---
    info = body.get("KinesisBatchInfo") or {}
    expected_info = {"shardId": shard_id, "startSequenceNumber": seq, "endSequenceNumber": seq,
                     "batchSize": 1, "streamArn": stream["arn"]}
    got_info = {k: info.get(k) for k in expected_info}
    assert got_info == expected_info, (
        f"KinesisBatchInfo must point at exactly the failed record:\nexpected {expected_info!r}\n"
        f"got      {got_info!r}\nfull body {body!r}"
    )
    assert "approximateArrivalOfFirstRecord" in info and "approximateArrivalOfLastRecord" in info, (
        f"KinesisBatchInfo must carry both arrival timestamps, got keys {sorted(info)!r}"
    )

    rc = body.get("requestContext") or {}
    assert rc.get("condition") == "RetryAttemptsExhausted", (
        f"MaximumRetryAttempts=0 exhausts on the first attempt; condition must be "
        f"RetryAttemptsExhausted, got {rc.get('condition')!r} in {body!r}"
    )
    assert rc.get("approximateInvokeCount") == 1, (
        f"MaximumRetryAttempts=0 means exactly one invocation; got {rc.get('approximateInvokeCount')!r}"
    )
    assert str(rc.get("functionArn", "")).split(":")[6:7] == [fn["name"]], (
        f"requestContext.functionArn must name {fn['name']!r}, got {rc.get('functionArn')!r}"
    )
    rsp = body.get("responseContext") or {}
    assert rsp.get("functionError") == "Unhandled", (
        f"a raised exception is reported as functionError Unhandled, got {rsp!r}"
    )

    # --- and the S3-only addition: the entire original invocation payload ---
    assert "payload" in body, (
        f"an S3 OnFailure destination must carry the full invocation payload the SQS/SNS "
        f"destinations never get; keys were {sorted(body)!r}"
    )
    invocation = json.loads(body["payload"]) if isinstance(body["payload"], str) else body["payload"]
    records = invocation.get("Records", [])
    assert len(records) == 1 and records[0].get("kinesis", {}).get("sequenceNumber") == seq, (
        f"the embedded payload must be the ORIGINAL invocation event for sequence {seq!r}, got "
        f"{records!r}"
    )
    decoded = json.loads(base64.b64decode(records[0]["kinesis"]["data"]))
    assert decoded == payload, (
        f"the embedded payload's record data must decode to {payload!r}, got {decoded!r}"
    )


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate holds; raises TimeoutError at the deadline, capped by the run
    budget."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not observed within {timeout_s:.0f}s; last saw {last!r}")


def _err(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _swallow(fn) -> None:
    """Teardown-only: an already-gone resource is fine; anything else is a named leak."""
    try:
        fn()
    except ClientError as exc:
        if _err(exc) not in ("ResourceNotFoundException", "NoSuchBucket"):
            raise RuntimeError(f"teardown step failed: {exc}") from exc


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-xsvc-{kind}-")


def _create_stream(ctx) -> dict[str, str]:
    """A one-shard Kinesis stream (one shard = one ordered sequence, one in-flight batch)."""
    kinesis = ctx.client("kinesis")
    name = _xname(ctx, "kin")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: _swallow(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)))
    summary = _poll_until(
        ctx, lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda d: d.get("StreamStatus") == "ACTIVE",
        timeout_s=120, interval_s=3.0, description=f"Kinesis stream {name} ACTIVE",
    )
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return {"name": name, "arn": summary["StreamARN"]}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "dest")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket,
                              Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    _swallow(lambda: s3.delete_bucket(Bucket=bucket))


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if _err(exc) != "NoSuchEntity":
            raise RuntimeError(f"IAM role {role_name}: {exc}") from exc


def _reap_log_group(ctx, fn_name: str) -> None:
    """delete_function leaves /aws/lambda/<fn>, and a buffered flush can RECREATE it after a
    delete, so reap in a loop until it stays absent for three consecutive reads."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    deadline = time.monotonic() + 45
    absent = 0
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=group)
            absent = 0
        except ClientError as exc:
            if _err(exc) != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group}: {exc}") from exc
            absent += 1
            if absent >= 3:
                return
        time.sleep(5)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_lambda(ctx, handler_code: str, *, statements: list[dict]) -> dict[str, str]:
    """A Lambda plus an execution role scoped to `statements`; logs are always allowed."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    policy = [{"Effect": "Allow",
               "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
               "Resource": "arn:aws:logs:*:*:*"}]
    policy += [{"Effect": "Allow", **s} for s in statements]
    role_name = _xname(ctx, "role")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy}))

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code).strip() + "\n")
    name = _xname(ctx, "fn")
    # Registered BEFORE the create so LIFO runs it AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))

    def _attempt():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="lambda_function.handler", Code={"ZipFile": buf.getvalue()},
                Timeout=30, MemorySize=128, Tags={"sim2real": CHECK},
            )
        except ClientError as exc:
            if (_err(exc) == "InvalidParameterValueException"
                    and "cannot be assumed" in exc.response["Error"].get("Message", "")):
                return None
            raise

    created = _poll_until(ctx, _attempt, lambda r: r is not None, timeout_s=90, interval_s=4.0,
                          description=f"CreateFunction {name} past the role-propagation window")
    ctx.on_cleanup(lambda: _swallow(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                lambda c: c.get("State") == "Active", timeout_s=120, interval_s=3.0,
                description=f"Lambda {name} State Active")
    return {"name": name, "arn": created["FunctionArn"]}


def _delete_esm(ctx, uuid_: str) -> None:
    """An ESM still Creating/Enabling refuses deletion with ResourceInUseException; retry, bounded."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            lam.delete_event_source_mapping(UUID=uuid_)
            return
        except ClientError as exc:
            if _err(exc) == "ResourceNotFoundException":
                return
            if _err(exc) != "ResourceInUseException":
                raise RuntimeError(f"event source mapping {uuid_}: {exc}") from exc
        time.sleep(5)
    raise RuntimeError(f"event source mapping {uuid_} still in use after 90s")


def _create_esm(ctx, fn_name: str, source_arn: str, **params) -> str:
    """CreateEventSourceMapping, retried while a fresh role's permissions propagate (bounded).

    Does not wait for Enabled: the downstream effect wait covers activation."""
    lam = ctx.client("lambda")
    seen: list[str] = []

    def _attempt():
        try:
            return lam.create_event_source_mapping(FunctionName=fn_name, EventSourceArn=source_arn,
                                                   Enabled=True, **params)
        except ClientError as exc:
            if _err(exc) == "InvalidParameterValueException":
                seen.append(str(exc))
                return None
            raise

    try:
        resp = _poll_until(ctx, _attempt, lambda r: r is not None, timeout_s=90, interval_s=5.0,
                           description="CreateEventSourceMapping past IAM propagation")
    except TimeoutError as exc:
        raise TimeoutError(f"{exc}; last refusal {seen[-1:]!r}") from None
    ctx.on_cleanup(lambda: _delete_esm(ctx, resp["UUID"]))
    return resp["UUID"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
