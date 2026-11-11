"""function-sdk-creates-heads-lists-and-deletes-a-bucket."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-creates-heads-lists-and-deletes-a-bucket"
GROUP = "data-plane"
SERVICES = ["lambda", "s3"]

_RUNTIME = "python3.12"
_SOURCE_FILE = "index.py"
_HANDLER = """\
import os
import time
import boto3
from botocore.exceptions import ClientError

def _refusal(call):
    try:
        call()
        return None
    except ClientError as exc:
        return {"code": exc.response["Error"]["Code"],
                "status": exc.response["ResponseMetadata"]["HTTPStatusCode"]}

def _named(s3, bucket):
    return [b["Name"] for b in s3.list_buckets(Prefix=bucket)["Buckets"]]

def handler(event, context):
    s3 = boto3.client("s3")
    bucket = event["bucket"]
    if event["op"] == "probe":
        return {"named": _named(s3, bucket)}
    region = os.environ["AWS_REGION"]
    kw = {} if region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": region}}
    created = s3.create_bucket(Bucket=bucket, **kw)
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": event["tag"]}]})
    head = s3.head_bucket(Bucket=bucket)
    named = _named(s3, bucket)
    deadline = time.monotonic() + 20
    while not named and time.monotonic() < deadline:
        time.sleep(1)
        named = _named(s3, bucket)
    deleted = s3.delete_bucket(Bucket=bucket)
    gone = _refusal(lambda: s3.head_bucket(Bucket=bucket))
    deadline = time.monotonic() + 20
    while gone is None and time.monotonic() < deadline:
        time.sleep(1)
        gone = _refusal(lambda: s3.head_bucket(Bucket=bucket))
    return {"created": created["ResponseMetadata"]["HTTPStatusCode"],
            "head": head["ResponseMetadata"]["HTTPStatusCode"], "named": named,
            "deleted": deleted["ResponseMetadata"]["HTTPStatusCode"], "gone": gone}
"""


@tags("axis:happy-path", "cap:c3", "plane:control")
def run(ctx) -> None:
    """A function's SDK manages a bucket's whole lifecycle: CreateBucket, HeadBucket, ListBuckets
    with the bucket's name as Prefix naming only it, DeleteBucket, and a HeadBucket on the deleted
    bucket refused with 404.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
    """
    s3 = ctx.client("s3")
    part = _partition(ctx)
    bucket = ctx.unique_name("sim2real-xsvc-fb-")
    ctx.on_cleanup(_teardown(_empty_and_delete(s3, bucket), "NoSuchBucket"))
    role = _execution_role(ctx, [
        {"Effect": "Allow", "Action": ["s3:CreateBucket", "s3:PutBucketTagging", "s3:ListBucket",
                                       "s3:DeleteBucket"],
         "Resource": f"arn:{part}:s3:::{bucket}"},
        {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)

    # The read-only probe rides out the grant's propagation; the lifecycle then runs exactly once.
    probe = _invoke_granted(ctx, fn["name"], {"op": "probe", "bucket": bucket})
    assert probe["named"] == [], f"ListBuckets named {probe['named']!r} before CreateBucket"
    err, out = _invoke(ctx, fn["name"], {"op": "lifecycle", "bucket": bucket, "tag": CHECK})
    assert err is None, f"the lifecycle function failed: {err!r} {out!r}"
    assert out["created"] == 200, f"CreateBucket answered {out['created']!r}"
    assert out["head"] == 200, f"HeadBucket on the new bucket answered {out['head']!r}"
    assert out["named"] == [bucket], f"ListBuckets with its name as Prefix named {out['named']!r}"
    assert out["deleted"] == 204, f"DeleteBucket answered {out['deleted']!r}"
    assert out["gone"] == {"code": "404", "status": 404}, (
        f"HeadBucket on the deleted bucket was {out['gone']!r}, not a 404 refusal")
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        gone = (exc.response["Error"]["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"])
    else:
        gone = None
    assert gone == ("404", 404), f"the caller's HeadBucket on the deleted bucket was {gone!r}"


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
        zf.writestr(_SOURCE_FILE, textwrap.dedent(code))
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


def _function(ctx, role_arn, code, *, timeout=60) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}

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


def _denied(result) -> bool:
    """Whether an invoke's payload shows a refusal the role's still-propagating grants explain."""
    text = json.dumps(result[1])
    return "AccessDenied" in text or '"status": 403' in text or '"code": "403"' in text


def _invoke_granted(ctx, fn, event) -> dict:
    """The payload of ``fn`` once the role's grants are effective; any other failure raises."""
    err, out = _poll(lambda: _invoke(ctx, fn, event), lambda r: not _denied(r),
                     timeout_s=90, interval_s=5, what="the role's s3 grants are effective")
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


def _empty_and_delete(s3, name):
    """Delete every object of ``name``, then the bucket."""

    def undo() -> None:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    return undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
