"""function-sdk-put-outside-granted-prefix-denied-as-function-error."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-put-outside-granted-prefix-denied-as-function-error"
GROUP = "permission-chain"
SERVICES = ["lambda", "s3"]

_HANDLER = """\
import boto3

def handler(event, context):
    r = boto3.client("s3").put_object(Bucket=event["bucket"], Key=event["key"],
                                      Body=event["body"].encode())
    return {"etag": r["ETag"]}
"""


def _error(fn) -> tuple:
    """(code, HTTP status) ``fn`` raises; an unexpected success raises naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Function SDK calls act as the execution role scoped to one S3 prefix: a PutObject under it lands
    (bytes and ETag read back), while a PutObject elsewhere fails the invoke as Unhandled with S3's
    exact AccessDenied message for the assumed-role session, and no object exists.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-exceptions.html
    """
    s3 = ctx.client("s3")
    bucket = _bucket(ctx)
    part = _partition(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "s3:PutObject",
         "Resource": f"arn:{part}:s3:::{bucket}/allowed/*"},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)

    body = ctx.unique_name("payload-")
    err, out = _poll(
        lambda: _invoke(ctx, fn["name"], {"bucket": bucket, "key": "allowed/obj", "body": body}),
        lambda r: r[0] is None or "AccessDenied" not in json.dumps(r[1]),
        timeout_s=90, interval_s=5, what="the role's s3:PutObject grant is effective")
    assert err is None, f"the permitted PutObject failed the invocation: {err!r} {out!r}"
    got = s3.get_object(Bucket=bucket, Key="allowed/obj")
    assert got["Body"].read() == body.encode(), "the object the function wrote reads back differently"
    assert got["ETag"] == out["etag"], f"ETag {got['ETag']!r} != the function's {out['etag']!r}"

    err, out = _invoke(ctx, fn["name"], {"bucket": bucket, "key": "denied/obj", "body": body})
    assert err == "Unhandled", f"the unpermitted PutObject gave FunctionError {err!r}: {out!r}"
    principal = f"arn:{part}:sts::{ctx.account}:assumed-role/{role['name']}/{fn['name']}"
    want = (f"An error occurred (AccessDenied) when calling the PutObject operation: User: "
            f"{principal} is not authorized to perform: s3:PutObject on resource: "
            f"\"arn:{part}:s3:::{bucket}/denied/obj\" because no identity-based policy allows "
            f"the s3:PutObject action")
    assert out.get("errorMessage") == want, (
        f"errorMessage {out.get('errorMessage')!r}, expected {want!r}")
    code, status = _error(lambda: s3.head_object(Bucket=bucket, Key="denied/obj"))
    assert code == "404", f"HeadObject on the denied key gave code {code!r}, expected absent"
    assert status == 404, f"HeadObject on the denied key gave HTTP {status!r}"


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


def _bucket(ctx) -> str:
    """A bucket of ours, emptied and deleted at cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-b-")
    kw = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=name, **kw)

    def empty_and_delete():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown(empty_and_delete, "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
