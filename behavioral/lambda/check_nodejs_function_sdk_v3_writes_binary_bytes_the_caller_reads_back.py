"""nodejs-function-sdk-v3-writes-binary-bytes-the-caller-reads-back."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-function-sdk-v3-writes-binary-bytes-the-caller-reads-back"
GROUP = "compute"
SERVICES = ["lambda"]

_BASIC_EXEC_POLICY = "arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
#: What GetFunction's error probe answers while the function still reads back.
_SUCCEEDED = ("succeeded", "the call succeeded", 200)

_HANDLER = """\
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';

export const handler = async (event) => {
  const ident = await new STSClient({}).send(new GetCallerIdentityCommand({}));
  try {
    const out = await new S3Client({}).send(new PutObjectCommand({
      Bucket: event.bucket, Key: event.key, Body: Buffer.from(event.body_b64, 'base64'),
      ContentType: 'application/octet-stream',
    }));
    return { account: ident.Account, etag: out.ETag };
  } catch (e) {
    return { account: ident.Account, put_error: e.name };
  }
};
"""


def _zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.mjs", code)
    return buf.getvalue()


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Node.js function using the runtime's AWS SDK v3 with no endpoint reaches the caller's
    account: STS names it, and the binary object it writes under a nested key reads back byte for
    byte with the ETag the function saw, the MD5 of those bytes."""
    lam = ctx.client("lambda", config=Config(read_timeout=40, retries={"max_attempts": 0}))
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    account = ctx.account

    bucket = ctx.unique_name("sim2real-behav-fnsdk-")
    create_kwargs = {"Bucket": bucket}
    # us-east-1 is the one region that takes no LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(s3, bucket))

    role_arn = _execution_role(ctx, iam, bucket)
    fn = ctx.unique_name("sim2real-behav-fnsdk-")
    _create_function(
        lam,
        FunctionName=fn,
        Runtime="nodejs22.x",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zip(_HANDLER)},
        MemorySize=256,
        Timeout=60,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_log_group_if_exists(ctx.client("logs"), f"/aws/lambda/{fn}"))
    ctx.on_cleanup(lambda: _delete_function_if_exists(lam, fn))
    _wait_active(lam, fn)

    marker = ctx.unique_name("marker-")
    body = hashlib.sha256(marker.encode()).digest() + bytes(range(256))
    key = f"nested/dir/{marker}.bin"
    event = {"bucket": bucket, "key": key, "body_b64": base64.b64encode(body).decode()}
    # The execution role's inline policy is eventually consistent on real AWS.
    out = _poll(lambda: _invoke(lam, fn, event), lambda r: r.get("put_error") != "AccessDenied",
                timeout_s=40, interval_s=5, what="the function's PutObject is authorized")
    assert "put_error" not in out, (
        f"the function's own PutObjectCommand to the check's bucket failed with "
        f"{out['put_error']!r}: the SDK inside the function did not reach this target's S3"
    )
    assert out.get("account") == account, (
        f"the function's own GetCallerIdentityCommand reported account {out.get('account')!r}, "
        f"expected {account!r}: the SDK inside the function did not reach this target"
    )
    want_etag = f'"{hashlib.md5(body).hexdigest()}"'
    assert out.get("etag") == want_etag, f"the function saw ETag {out.get('etag')!r}, expected {want_etag!r}"
    got = s3.get_object(Bucket=bucket, Key=key)
    data = got["Body"].read()
    assert data == body, f"the object reads back {len(data)} bytes {data[:16]!r}..., expected {len(body)} bytes {body[:16]!r}..."
    assert got["ETag"] == want_etag, f"GetObject ETag {got['ETag']!r}, expected {want_etag!r}"
    assert got["ContentType"] == "application/octet-stream", f"GetObject ContentType {got['ContentType']!r}"

    lam.delete_function(FunctionName=fn)
    code, message, status = _poll(
        lambda: _get_function_error(lam, fn), lambda r: r != _SUCCEEDED,
        timeout_s=40, interval_s=2, what="GetFunction refuses the deleted function",
    )
    want = ("ResourceNotFoundException",
            f"Function not found: arn:{_partition(ctx)}:lambda:{ctx.region}:{account}:function:{fn}", 404)
    assert (code, message, status) == want, f"GetFunction on the deleted function answered {(code, message, status)!r}, expected {want!r}"


def _execution_role(ctx, iam, bucket) -> str:
    """A Lambda execution role with basic logging and PutObject on the check's bucket."""
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_no_such_entity(lambda: iam.delete_role(RoleName=name)))
    partition = _partition(ctx)
    basic_exec = _BASIC_EXEC_POLICY.format(partition=partition)
    iam.attach_role_policy(RoleName=name, PolicyArn=basic_exec)
    ctx.on_cleanup(lambda: _ignore_no_such_entity(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=basic_exec)))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:PutObject",
                       "Resource": f"arn:{partition}:s3:::{bucket}/*"}],
    }
    iam.put_role_policy(RoleName=name, PolicyName="sim2real-put", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _ignore_no_such_entity(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-put")))
    return arn


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    deadline = time.monotonic() + 40
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


def _wait_active(lam, fn, timeout_s=40) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("State") == "Failed":
            raise AssertionError(f"function {fn} entered Failed: {last.get('StateReason')!r}")
        if last.get("State", "Active") == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {fn} did not reach Active within {timeout_s}s: {last!r}")


def _invoke(lam, fn, event) -> dict:
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(event).encode())
    raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"the function raised ({resp['FunctionError']}): {raw.decode(errors='replace')[:600]}"
        )
    out = json.loads(raw) if raw else None
    assert isinstance(out, dict), f"the function returned {raw[:300]!r}, expected a JSON object"
    return out


def _poll(probe, done, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")


def _get_function_error(lam, fn):
    """(code, message, HTTP status) of GetFunction's error, or _SUCCEEDED while it reads back."""
    try:
        lam.get_function(FunctionName=fn)
        return _SUCCEEDED
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message"), e.response["ResponseMetadata"].get("HTTPStatusCode")


def _ignore_no_such_entity(call) -> None:
    try:
        call()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_function_if_exists(lam, fn) -> None:
    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_log_group_if_exists(logs, name) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_bucket_if_exists(s3, bucket) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
