"""s3-object-version-pins-the-code-a-function-runs."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-object-version-pins-the-code-a-function-runs"
GROUP = 'compute'
SERVICES = ['lambda']
POLL_BUDGET_S = 40
_KEY = "bundle/code.zip"

_CODE_SHA256 = """\
import hashlib, json
def handler(event, context):
    data = json.dumps(event, sort_keys=True).encode()
    return {"algo": "sha256", "digest": hashlib.sha256(data).hexdigest()}
"""

_CODE_MD5 = """\
import hashlib, json
def handler(event, context):
    data = json.dumps(event, sort_keys=True).encode()
    return {"algo": "md5", "digest": hashlib.md5(data).hexdigest(), "keys": len(event)}
"""


def _make_zip(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _b64_sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _teardown(undo, *not_found):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _execution_role(ctx):
    """This check's own Lambda execution role; the partition comes from the role's ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = f"arn:{arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _versioned_bucket(ctx, s3):
    """A versioned bucket this check owns; teardown removes every object version, then the bucket."""
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region that takes no LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def purge():
        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
                for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(purge)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    deadline = time.monotonic() + 40
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _wait_ready(lam, fn, timeout_s=POLL_BUDGET_S):
    """Poll until Active with no update in flight; raise on Failed or timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed" or last.get("LastUpdateStatus") == "Failed":
            raise AssertionError(f"{fn} failed: {last.get('StateReason')!r} {last.get('LastUpdateStatusReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active/Successful within {timeout_s}s. Last: {last!r}")


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode())
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}")
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function created from an older S3ObjectVersion runs that version's code, not the key's
    current object, and its CodeSha256 is that zip's digest; UpdateFunctionCode naming the newer
    version switches both the computation and CodeSha256.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_FunctionCode.html
    """
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")
    bucket = _versioned_bucket(ctx, s3)
    zip_old, zip_new = _make_zip(_CODE_SHA256), _make_zip(_CODE_MD5)
    v_old = s3.put_object(Bucket=bucket, Key=_KEY, Body=zip_old)["VersionId"]
    v_new = s3.put_object(Bucket=bucket, Key=_KEY, Body=zip_new)["VersionId"]
    assert v_old != v_new, f"two PutObjects to a versioned bucket returned one VersionId {v_old!r}"

    fn = ctx.unique_name("sim2real-behav-fn-")
    created = _create_function(
        lam, FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=_execution_role(ctx),
        Code={"S3Bucket": bucket, "S3Key": _KEY, "S3ObjectVersion": v_old}, Timeout=15,
        Tags={"sim2real": CHECK},
    )
    logs = ctx.client("logs")
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{fn}"),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn), "ResourceNotFoundException"))
    assert created["CodeSha256"] == _b64_sha256(zip_old), (
        f"CreateFunction CodeSha256 {created['CodeSha256']!r}, expected the pinned version's "
        f"{_b64_sha256(zip_old)!r} (current object's is {_b64_sha256(zip_new)!r})"
    )
    _wait_ready(lam, fn)

    payload = {"order": ctx.unique_name("o-"), "qty": 3, "sku": "Z-9"}
    data = json.dumps(payload, sort_keys=True).encode()
    got = _invoke_sync(lam, fn, payload)
    want = {"algo": "sha256", "digest": hashlib.sha256(data).hexdigest()}
    assert got == want, f"the function created from the older object version returned {got!r}, expected {want!r}"

    updated = lam.update_function_code(FunctionName=fn, S3Bucket=bucket, S3Key=_KEY, S3ObjectVersion=v_new)
    assert updated["CodeSha256"] == _b64_sha256(zip_new), (
        f"UpdateFunctionCode CodeSha256 {updated['CodeSha256']!r}, expected {_b64_sha256(zip_new)!r}"
    )
    conf = _wait_ready(lam, fn)
    assert conf["CodeSha256"] == _b64_sha256(zip_new), f"GetFunctionConfiguration CodeSha256 {conf['CodeSha256']!r}"
    got = _invoke_sync(lam, fn, payload)
    want = {"algo": "md5", "digest": hashlib.md5(data).hexdigest(), "keys": 3}
    assert got == want, f"after UpdateFunctionCode to the newer object version the function returned {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
