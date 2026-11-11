"""kinesis-esm-parallelization-factor-above-ten-rejected."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-esm-parallelization-factor-above-ten-rejected"
GROUP = "event-propagation"
SERVICES = ["kinesis", "lambda"]

_HANDLER = """\
def handler(event, context):
    return {"n": len(event.get("Records", []))}
"""


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn()`` raises; an unexpected success raises."""
    try:
        out = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, the call succeeded: {out!r}")


def _mappings(lam, fn) -> list:
    out = []
    for page in lam.get_paginator("list_event_source_mappings").paginate(FunctionName=fn):
        out.extend(page["EventSourceMappings"])
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping with ParallelizationFactor 11 is refused with a ValidationException
    naming the bound of 10 and creates no mapping; the same request with 10 creates a mapping that
    reports 10.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html
    """
    lam = ctx.client("lambda")
    src = _stream(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary",
                                       "kinesis:GetRecords", "kinesis:GetShardIterator",
                                       "kinesis:ListShards", "kinesis:ListStreams"],
         "Resource": src["arn"]}])
    fn = _function(ctx, role["arn"], _HANDLER)

    code, msg = _error(lambda: lam.create_event_source_mapping(
        EventSourceArn=src["arn"], FunctionName=fn["name"], StartingPosition="LATEST",
        ParallelizationFactor=11))
    assert (code, msg) == ("ValidationException", (
        "1 validation error detected: Value '11' at 'parallelizationFactor' failed to satisfy "
        "constraint: Member must have value less than or equal to 10")), (
        f"ParallelizationFactor 11 refused with {code!r}: {msg!r}")
    assert _mappings(lam, fn["name"]) == [], (
        f"the refused request left mappings: {_mappings(lam, fn['name'])!r}")

    esm = _mapping(ctx, EventSourceArn=src["arn"], FunctionName=fn["name"],
                   StartingPosition="LATEST", ParallelizationFactor=10)
    listed = _mappings(lam, fn["name"])
    assert [(m["UUID"], m["ParallelizationFactor"]) for m in listed] == [(esm["UUID"], 10)], (
        f"after the accepted request the function lists {listed!r}")


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


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _partition(ctx) -> str:
    """The caller's partition, read off its own ARN, never a literal."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"unparseable caller ARN {arn!r}"
    return parts[1]


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, env=None, timeout=30) -> dict:
    """A python3.12 function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}
    if env:
        kwargs["Environment"] = {"Variables": env}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _mapping(ctx, **kwargs) -> dict:
    """CreateEventSourceMapping through the role-propagation window, then poll it to Enabled."""
    lam = ctx.client("lambda")

    def create():
        try:
            return lam.create_event_source_mapping(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    esm = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateEventSourceMapping accepts the fresh execution role")
    uuid = esm["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    want = "Enabled" if kwargs.get("Enabled", True) else "Disabled"
    _poll(lambda: lam.get_event_source_mapping(UUID=uuid)["State"], lambda s: s == want,
          timeout_s=120, interval_s=2, what=f"mapping {uuid} reaches {want}")
    return esm


def _stream(ctx, shards=1) -> dict:
    """A provisioned stream of ours with ``shards`` shards, ACTIVE, its delete registered."""
    kin = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-ks-")
    kin.create_stream(StreamName=name, ShardCount=shards,
                      StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(_teardown(lambda: kin.delete_stream(StreamName=name,
                                                       EnforceConsumerDeletion=True),
                             "ResourceNotFoundException"))
    kin.get_waiter("stream_exists").wait(StreamName=name,
                                         WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    desc = kin.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    kin.add_tags_to_stream(StreamName=name, Tags={"sim2real": CHECK})
    return {"name": name, "arn": desc["StreamARN"]}




if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
