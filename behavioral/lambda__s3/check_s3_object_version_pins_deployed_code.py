"""s3-object-version-pins-deployed-code."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-object-version-pins-deployed-code"
GROUP = 'packaging'
SERVICES = ["lambda", "s3", "iam"]

CODE = """\
MARKER = "%s"


def handler(event, context):
    return {"marker": MARKER}
"""


def _make_bucket(ctx, s3, *, versioned: bool = False) -> str:
    """This check's own bucket; its teardown deletes every object version, then the bucket."""
    bucket = ctx.unique_name("sim2real-behav-l6-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for item in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=item["Key"], VersionId=item["VersionId"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_teardown(_empty_and_delete, "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


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


def _zip(files: dict) -> bytes:
    """A deterministic archive: fixed timestamps and modes, so equal sources give equal bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)
    return buf.getvalue()


def _make_role(ctx, iam) -> str:
    """This check's own execution role. It carries no policy: the handlers write no logs, so
    Lambda creates no /aws/lambda/<fn> log group that could outlive the check."""
    name = ctx.unique_name("sim2real-behav-l6-")
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs) -> dict:
    """CreateFunction retrying ONLY the documented role-propagation refusal; waits until ready."""
    name = kwargs["FunctionName"]
    deadline = time.monotonic() + 90.0
    while True:
        try:
            created = lam.create_function(**kwargs)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "InvalidParameterValueException" or err.get("Message") != _ROLE_NOT_READY:
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"CreateFunction kept failing on role propagation: {err!r}")
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_ready(lam, name)
    return created


def _wait_ready(lam, name: str, qualifier: str = "$LATEST", timeout_s: float = 120.0) -> dict:
    """Poll until the function (or one version of it) is Active with its last update Successful."""
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=name, Qualifier=qualifier)
        if cfg.get("State") == "Failed" or cfg.get("LastUpdateStatus") == "Failed":
            raise AssertionError(
                f"{qualifier} failed: {cfg.get('StateReason')!r} {cfg.get('LastUpdateStatusReason')!r}"
            )
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{qualifier} not ready within {timeout_s}s: State={cfg.get('State')!r} "
                f"LastUpdateStatus={cfg.get('LastUpdateStatus')!r}"
            )
        time.sleep(1)


def _invoke(lam, target: str, **kwargs):
    """A synchronous invoke that must succeed: returns (ExecutedVersion, decoded body)."""
    resp = lam.invoke(FunctionName=target, Payload=b"{}", **kwargs)
    payload = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"invoke of {kwargs or target!r} returned {resp['StatusCode']!r}"
    assert "FunctionError" not in resp, (
        f"invoke reported FunctionError={resp.get('FunctionError')!r}: {payload!r}"
    )
    return resp.get("ExecutedVersion"), json.loads(payload)


def _error(fn):
    """(code, message, http status) of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"),
                exc.response["ResponseMetadata"]["HTTPStatusCode"])
    if isinstance(result, dict) and hasattr(result.get("Payload"), "read"):
        result = {**result, "Payload": result["Payload"].read()}
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3ObjectVersion selects the deployed bytes: a function created from the older object version
    stores its CodeSha256 and runs its code, omitting the version deploys the current object, and
    naming the old version again rolls back.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_FunctionCode.html
    """
    lam, s3 = ctx.client("lambda"), ctx.client("s3")
    role = _make_role(ctx, ctx.client("iam"))
    bucket = _make_bucket(ctx, s3, versioned=True)
    old_zip, new_zip = _zip({"index.py": CODE % "older"}), _zip({"index.py": CODE % "newer"})
    old_vid = s3.put_object(Bucket=bucket, Key="code.zip", Body=old_zip)["VersionId"]
    new_vid = s3.put_object(Bucket=bucket, Key="code.zip", Body=new_zip)["VersionId"]
    assert old_vid != new_vid, f"a versioned bucket must mint distinct VersionIds, got {old_vid!r} twice"

    fn = ctx.unique_name("sim2real-behav-l6-s3ver-")
    created = _create_function(ctx, lam, FunctionName=fn, Runtime="python3.12",
                               Handler="index.handler", Role=role, Timeout=10, Tags={"sim2real": CHECK},
                               Code={"S3Bucket": bucket, "S3Key": "code.zip", "S3ObjectVersion": old_vid})
    sha = {z: base64.b64encode(hashlib.sha256(z).digest()).decode() for z in (old_zip, new_zip)}
    assert created["CodeSha256"] == sha[old_zip], "the pinned object version's bytes must be stored"
    pinned = _invoke(lam, fn)
    assert pinned == ("$LATEST", {"marker": "older"}), (
        f"a function created from the older object version must run 'older', got {pinned!r}"
    )

    lam.update_function_code(FunctionName=fn, S3Bucket=bucket, S3Key="code.zip")
    _wait_ready(lam, fn)
    current = _invoke(lam, fn)
    assert current == ("$LATEST", {"marker": "newer"}), (
        f"without S3ObjectVersion the key's current object must deploy, got {current!r}"
    )
    rolled = lam.update_function_code(FunctionName=fn, S3Bucket=bucket, S3Key="code.zip",
                                      S3ObjectVersion=old_vid)
    assert rolled["CodeSha256"] == sha[old_zip], "naming the old version again must store its bytes"
    _wait_ready(lam, fn)
    back = _invoke(lam, fn)
    assert back == ("$LATEST", {"marker": "older"}), f"rolling back by object version ran {back!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
