"""kinesis-esm-default-maximum-retry-attempts-is-minus-one."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-default-maximum-retry-attempts-is-minus-one"
GROUP = "event-source-mapping"
SERVICES = ["kinesis", "lambda"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll(ctx, probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises TimeoutError at the capped deadline."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s:.0f}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _execution_role(ctx, statements) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ktra-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
        "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"]}


def _function(ctx, role_arn, code, *, env=None) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-ktra-fn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": 30,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValueException" and "cannot be assumed" in err.get(
                    "Message", ""):
                return None
            raise

    out = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _stream(ctx, shards=1) -> dict:
    kin = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-ktra-ks-")
    kin.create_stream(StreamName=name, ShardCount=shards,
                      StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(_teardown(lambda: kin.delete_stream(StreamName=name,
                                                       EnforceConsumerDeletion=True),
                             "ResourceNotFoundException"))
    desc = _poll(ctx, lambda: kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
                 lambda d: d.get("StreamStatus") == "ACTIVE", timeout_s=180, interval_s=2,
                 what=f"stream {name} ACTIVE")
    kin.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return {"name": name, "arn": desc["StreamARN"]}


_SINK_HANDLER = """\
import json, os
import boto3

def handler(event, context):
    boto3.client("kinesis").put_record(StreamName=os.environ["SINK"], PartitionKey="sink",
                                       Data=json.dumps({"records": event["Records"]}).encode())
    return {"n": len(event["Records"])}
"""


def _sink_batches(ctx, sink) -> list:
    kin = ctx.client("kinesis")
    shard = kin.list_shards(StreamName=sink["name"])["Shards"][0]["ShardId"]
    it = kin.get_shard_iterator(StreamName=sink["name"], ShardId=shard,
                                ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    out = []
    while it:
        page = kin.get_records(ShardIterator=it, Limit=1000)
        out.extend(json.loads(r["Data"]) for r in page["Records"])
        if not page["Records"] and page.get("MillisBehindLatest", 0) == 0:
            break
        it = page.get("NextShardIterator")
    return out


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation",
      "concern:negative-classes", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Kinesis event source mapping created with no MaximumRetryAttempts reports -1 (unlimited
    retries) in both the create and the settled describe response, and still delivers records; a
    second mapping just above the documented maximum of 10000 is refused with ValidationException.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
    """
    lam = ctx.client("lambda")
    kin = ctx.client("kinesis")

    src = _stream(ctx)
    sink = _stream(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
                                       "kinesis:GetRecords", "kinesis:GetShardIterator",
                                       "kinesis:ListShards", "kinesis:ListStreams"],
         "Resource": src["arn"]},
        {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": sink["arn"]},
    ])
    fn = _function(ctx, role["arn"], _SINK_HANDLER, env={"SINK": sink["name"]})

    def create():
        try:
            return lam.create_event_source_mapping(
                EventSourceArn=src["arn"], FunctionName=fn["name"],
                StartingPosition="TRIM_HORIZON", BatchSize=10)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    esm = _poll(ctx, create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    assert esm.get("MaximumRetryAttempts") == -1, (
        f"CreateEventSourceMapping with no MaximumRetryAttempts reported "
        f"{esm.get('MaximumRetryAttempts')!r}, not -1"
    )

    settled = _poll(ctx, lambda: lam.get_event_source_mapping(UUID=uuid),
                    lambda m: m["State"] == "Enabled", timeout_s=120, interval_s=2,
                    what=f"mapping {uuid} reaches Enabled")
    assert settled.get("MaximumRetryAttempts") == -1, (
        f"the settled mapping reports MaximumRetryAttempts={settled.get('MaximumRetryAttempts')!r}"
        f", not -1"
    )

    # The default is not just a reported number: the mapping it describes is live and delivers.
    marker = ctx.unique_name("")
    kin.put_record(StreamName=src["name"], PartitionKey="p", Data=marker.encode())

    def delivered():
        for batch in _sink_batches(ctx, sink):
            for record in batch["records"]:
                data = record["kinesis"]["data"]
                if data and base64.b64decode(data) == marker.encode():
                    return True
        return False

    _poll(ctx, delivered, lambda ok: ok, timeout_s=120, interval_s=3,
          what="the marker record reaches the function through the -1 mapping")

    # ---- break exactly one thing: a second mapping just above the documented maximum ----
    try:
        lam.create_event_source_mapping(
            EventSourceArn=src["arn"], FunctionName=fn["name"], StartingPosition="TRIM_HORIZON",
            BatchSize=10, MaximumRetryAttempts=10001)
    except ClientError as exc:
        err = exc.response["Error"]
        code, message = err["Code"], err["Message"]
    else:
        raise AssertionError(
            "CreateEventSourceMapping with MaximumRetryAttempts=10001 was expected to be refused "
            "but it SUCCEEDED"
        )
    assert code == "ValidationException", (
        f"MaximumRetryAttempts=10001 was refused with {code!r}, not ValidationException: {message}"
    )
    assert message == (
        "1 validation error detected: Value '10001' at 'maximumRetryAttempts' failed to satisfy "
        "constraint: Member must have value less than or equal to 10000"
    ), f"unexpected refusal message: {message!r}"
    assert len(lam.list_event_source_mappings(FunctionName=fn["name"])["EventSourceMappings"]) == 1, (
        "the refused CreateEventSourceMapping left more than the one mapping this check created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
