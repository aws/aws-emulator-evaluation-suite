"""function-sdk-bucket-policy-round-trips."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "function-sdk-bucket-policy-round-trips"
GROUP = "data-plane"
SERVICES = ["lambda", "s3"]

_RUNTIME = "python3.12"
_SOURCE_FILE = "index.py"

_HANDLER = """\
import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    s3 = boto3.client("s3")
    b = event["bucket"]
    s3.put_bucket_policy(Bucket=b, Policy=event["policy"])
    got = s3.get_bucket_policy(Bucket=b)["Policy"]
    s3.delete_bucket_policy(Bucket=b)
    try:
        after = {"policy": s3.get_bucket_policy(Bucket=b)["Policy"]}
    except ClientError as exc:
        after = {"error": exc.response["Error"]["Code"],
                 "message": exc.response["Error"].get("Message")}
    return {"policy": got, "policy_type": type(got).__name__, "after_delete": after}
"""


@tags("axis:happy-path", "cap:c3", "plane:control")
def run(ctx) -> None:
    """A function's PutBucketPolicy, GetBucketPolicy and DeleteBucketPolicy round-trip a policy:
    it reads back as the same JSON document, and after the delete GetBucketPolicy answers
    NoSuchBucketPolicy.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html
    """
    part = _partition(ctx)
    bucket = _bucket(ctx)
    role = _execution_role(ctx, [
        {"Effect": "Allow",
         "Action": ["s3:PutBucketPolicy", "s3:GetBucketPolicy", "s3:DeleteBucketPolicy"],
         "Resource": f"arn:{part}:s3:::{bucket}"},
    ])
    fn = _function(ctx, role["arn"], _HANDLER)

    policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "AccountRootReads", "Effect": "Allow",
        "Principal": {"AWS": f"arn:{part}:iam::{ctx.account}:root"},
        "Action": "s3:GetObject", "Resource": f"arn:{part}:s3:::{bucket}/*"}]}
    out = _invoke_granted(ctx, fn["name"], {"bucket": bucket, "policy": json.dumps(policy)})
    assert out["policy_type"] == "str", f"GetBucketPolicy Policy must be a JSON string: {out!r}"
    assert json.loads(out["policy"]) == policy, (
        f"GetBucketPolicy read back {out['policy']!r}, put {policy!r}")
    want = {"error": "NoSuchBucketPolicy", "message": "The bucket policy does not exist"}
    assert out["after_delete"] == want, (
        f"GetBucketPolicy after DeleteBucketPolicy answered {out['after_delete']!r}, "
        f"expected {want!r}")


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


def _zip(code: str, extra=None) -> bytes:
    """The deployment package: the handler module plus ``extra`` files keyed by archive path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_SOURCE_FILE, textwrap.dedent(code))
        for path, body in (extra or {}).items():
            zf.writestr(path, body)
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


def _function(ctx, role_arn, code, *, timeout=60, memory=256, extra=None, environment=None) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code, extra)}, "Timeout": timeout,
              "MemorySize": memory, "Tags": {"sim2real": CHECK}}
    if environment:
        kwargs["Environment"] = {"Variables": environment}

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


def _invoke(ctx, fn, event=None, lam=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    lam = lam or ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
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


def _bucket(ctx) -> str:
    """A bucket of ours, emptied and deleted at cleanup."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-b-")
    # us-east-1 is not a region literal pin: CreateBucket rejects an explicit
    # LocationConstraint for that region specifically, so it is omitted only there.
    kw = {} if ctx.region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": ctx.region}}
    s3.create_bucket(Bucket=name, **kw)
    ctx.on_cleanup(_teardown(_empty_and_delete(s3, name), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
