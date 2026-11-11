"""function-sdk-put-to-unpermitted-table-denied-as-function-error."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-put-to-unpermitted-table-denied-as-function-error"
GROUP = "permission-chain"
SERVICES = ["dynamodb", "lambda"]

_HANDLER = """\
import boto3

def handler(event, context):
    boto3.client("dynamodb").put_item(TableName=event["table"], Item={
        "pk": {"S": event["pk"]}, "from": {"S": context.function_name}})
    return {"written": event["pk"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """In-function SDK calls act as the execution role: PutItem to the granted table lands, while to
    an ungranted table it fails the invoke as Unhandled with DynamoDB's exact AccessDeniedException
    text for the role's assumed-role session, and writes nothing.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-exceptions.html
    """
    ddb = ctx.client("dynamodb")
    allowed = _table(ctx)
    denied = _table(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": allowed["arn"]},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)
    part = _partition(ctx)

    pk = ctx.unique_name("ok-")
    err, out = _poll(lambda: _invoke(ctx, fn["name"], {"table": allowed["name"], "pk": pk}),
                     lambda r: r[0] is None or "AccessDenied" not in json.dumps(r[1]),
                     timeout_s=90, interval_s=5, what="the role's dynamodb:PutItem grant is effective")
    assert err is None, f"the permitted PutItem failed the invocation: {err!r} {out!r}"
    item = ddb.get_item(TableName=allowed["name"], Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")
    assert item == {"pk": {"S": pk}, "from": {"S": fn["name"]}}, f"the permitted table holds {item!r}"

    bad = ctx.unique_name("denied-")
    err, out = _invoke(ctx, fn["name"], {"table": denied["name"], "pk": bad})
    assert err == "Unhandled", f"the unpermitted PutItem gave FunctionError {err!r}: {out!r}"
    principal = f"arn:{part}:sts::{ctx.account}:assumed-role/{role['name']}/{fn['name']}"
    want = (f"An error occurred (AccessDeniedException) when calling the PutItem operation: User: "
            f"{principal} is not authorized to perform: dynamodb:PutItem on resource: "
            f"{denied['arn']} because no identity-based policy allows the dynamodb:PutItem action")
    assert out.get("errorMessage") == want, (
        f"errorMessage {out.get('errorMessage')!r}, expected {want!r}")
    stray = ddb.get_item(TableName=denied["name"], Key={"pk": {"S": bad}}, ConsistentRead=True)
    assert "Item" not in stray, f"the denied table holds {stray.get('Item')!r}"


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
