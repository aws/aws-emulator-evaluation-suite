"""ddb-stream-new-image-view-carries-only-after-images."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ddb-stream-new-image-view-carries-only-after-images"
GROUP = "event-propagation"
SERVICES = ["dynamodb", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Under StreamViewType NEW_IMAGE, INSERT and MODIFY records carry only the after-image and a
    REMOVE record carries no image; every record reports StreamViewType NEW_IMAGE.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.html
    """
    ddb = ctx.client("dynamodb")
    src = _table(ctx, view="NEW_IMAGE")
    sink = _table(ctx)
    role = _stream_role(ctx, src, sink)
    fn = _function(ctx, role["arn"], _SINK_HANDLER, env={"SINK": sink["name"]})
    _mapping(ctx, EventSourceArn=src["stream_arn"], FunctionName=fn["name"],
             StartingPosition="TRIM_HORIZON", BatchSize=10)

    k = ctx.unique_name("item-")
    v1 = {"pk": {"S": k}, "n": {"N": "1"}}
    v2 = {"pk": {"S": k}, "n": {"N": "2"}}
    ddb.put_item(TableName=src["name"], Item=v1)
    ddb.put_item(TableName=src["name"], Item=v2)
    ddb.delete_item(TableName=src["name"], Key={"pk": {"S": k}})

    def mine(rows):
        return [r for _, r in rows if r.get("dynamodb", {}).get("Keys") == {"pk": {"S": k}}]

    rows = _wait_records(ctx, sink, lambda rs: len(mine(rs)) >= 3, timeout_s=180,
                         what="three stream records for the item reach the function")
    recs = sorted(mine(rows), key=lambda r: int(r["dynamodb"]["SequenceNumber"]))
    assert [r["eventName"] for r in recs] == ["INSERT", "MODIFY", "REMOVE"], (
        f"eventNames in SequenceNumber order: {[r['eventName'] for r in recs]!r}")
    for r in recs:
        assert r["dynamodb"]["StreamViewType"] == "NEW_IMAGE", (
            f"StreamViewType {r['dynamodb']['StreamViewType']!r}")
    ins, mod, rem = (r["dynamodb"] for r in recs)
    assert ins.get("NewImage") == v1 and "OldImage" not in ins, f"INSERT under NEW_IMAGE: {ins!r}"
    assert mod.get("NewImage") == v2 and "OldImage" not in mod, f"MODIFY under NEW_IMAGE: {mod!r}"
    assert "NewImage" not in rem and "OldImage" not in rem, f"REMOVE under NEW_IMAGE carried an image: {rem!r}"


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


def _table(ctx, *, view=None) -> dict:
    """An on-demand table keyed on ``pk`` (S), with a stream of ``view`` when given, ACTIVE."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-xsvc-t-")
    kw = {}
    if view:
        kw["StreamSpecification"] = {"StreamEnabled": True, "StreamViewType": view}
    ddb.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                     AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}], **kw)
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    desc = ddb.describe_table(TableName=name)["Table"]
    return {"name": name, "arn": desc["TableArn"], "stream_arn": desc.get("LatestStreamArn")}


_SINK_HANDLER = """\
import json, os
import boto3

def handler(event, context):
    ddb = boto3.client("dynamodb")
    for record in event["Records"]:
        ddb.put_item(TableName=os.environ["SINK"], Item={
            "pk": {"S": os.environ.get("TAG", "") + record["eventID"]},
            "rec": {"S": json.dumps(record)}})
    return {"n": len(event["Records"])}
"""


def _stream_role(ctx, table, sink) -> dict:
    return _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["dynamodb:DescribeStream", "dynamodb:GetRecords",
                                       "dynamodb:GetShardIterator", "dynamodb:ListStreams"],
         "Resource": table["stream_arn"]},
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": sink["arn"]},
    ])


def _sink_records(ctx, sink) -> list:
    """Every (sink key, forwarded stream record) the function has written, read consistently."""
    ddb = ctx.client("dynamodb")
    out = []
    for page in ddb.get_paginator("scan").paginate(TableName=sink["name"], ConsistentRead=True):
        out.extend((i["pk"]["S"], json.loads(i["rec"]["S"])) for i in page["Items"])
    return out


def _wait_records(ctx, sink, done, *, timeout_s, what) -> list:
    return _poll(lambda: _sink_records(ctx, sink), done, timeout_s=timeout_s, interval_s=3,
                 what=what)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
