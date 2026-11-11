"""function-sdk-reads-what-the-caller-wrote."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-reads-what-the-caller-wrote"
GROUP = "data-plane"
SERVICES = ["lambda", "s3"]

_HANDLER = """\
import base64
import boto3

def handler(event, context):
    s3 = boto3.client("s3")
    obj = s3.get_object(Bucket=event["bucket"], Key=event["key"])
    keys = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(
        Bucket=event["bucket"], Prefix=event["prefix"]) for o in page.get("Contents", [])]
    return {"body": base64.b64encode(obj["Body"].read()).decode(), "etag": obj["ETag"],
            "metadata": obj["Metadata"], "contentType": obj["ContentType"], "keys": keys}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Function SDK calls with no endpoint read the caller's S3: the object is read inside the function
    byte for byte with its ETag, user metadata and Content-Type, and a prefix listing returns
    exactly the keys under that prefix.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/python-package.html
    """
    s3 = ctx.client("s3")
    bucket = _bucket(ctx)
    part = _partition(ctx)
    data = b"\x00\x01binary\xff" + ctx.unique_name("").encode()
    put = s3.put_object(Bucket=bucket, Key="in/a.bin", Body=data, ContentType="application/x-sim2real",
                        Metadata={"origin": "the-check", "n": "1"})
    s3.put_object(Bucket=bucket, Key="in/b.bin", Body=b"b")
    s3.put_object(Bucket=bucket, Key="out/c.bin", Body=b"c")
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:{part}:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:{part}:s3:::{bucket}"},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)

    event = {"bucket": bucket, "key": "in/a.bin", "prefix": "in/"}
    err, out = _poll(lambda: _invoke(ctx, fn["name"], event),
                     lambda r: r[0] is None or "AccessDenied" not in json.dumps(r[1]),
                     timeout_s=90, interval_s=5, what="the role's s3 read grants are effective")
    assert err is None, f"the function's reads failed: {err!r} {out!r}"
    assert base64.b64decode(out["body"]) == data, "the function read different bytes than were put"
    assert out["etag"] == put["ETag"], f"ETag {out['etag']!r} != PutObject's {put['ETag']!r}"
    assert out["metadata"] == {"origin": "the-check", "n": "1"}, f"metadata {out['metadata']!r}"
    assert out["contentType"] == "application/x-sim2real", f"ContentType {out['contentType']!r}"
    assert out["keys"] == ["in/a.bin", "in/b.bin"], f"the in-function listing was {out['keys']!r}"


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
    # us-east-1 is not a region literal pin: CreateBucket rejects an explicit
    # LocationConstraint for that region specifically, so it is omitted only there.
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
