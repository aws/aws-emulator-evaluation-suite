"""update-function-code-invalid-signature-rejected."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-function-code-invalid-signature-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateFunctionCode with code signed by a profile outside the ENFORCE code-signing config is
    rejected with CodeVerificationFailedException and not stored, while the same payload signed by
    the allowed profile deploys and runs.
    """
    signer = ctx.client("signer")
    lam = ctx.client("lambda")
    s3 = ctx.client("s3")

    allowed_profile = _put_signing_profile(ctx, signer)
    mismatch_profile = _put_signing_profile(ctx, signer)

    csc = lam.create_code_signing_config(
        AllowedPublishers={"SigningProfileVersionArns": [allowed_profile["profileVersionArn"]]},
        CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
    )
    csc_arn = csc["CodeSigningConfig"]["CodeSigningConfigArn"]
    ctx.on_cleanup(lambda: lam.delete_code_signing_config(CodeSigningConfigArn=csc_arn))

    fn = _create_function(ctx)
    lam.put_function_code_signing_config(CodeSigningConfigArn=csc_arn, FunctionName=fn["name"])
    ctx.on_cleanup(lambda: _safe(lambda: lam.delete_function_code_signing_config(FunctionName=fn["name"])))
    assert lam.get_function_code_signing_config(FunctionName=fn["name"])["CodeSigningConfigArn"] == csc_arn, (
        "the Enforce CodeSigningConfig did not attach"
    )

    bucket = _create_bucket(ctx, s3)

    # Positive control: the same kind of update, correctly signed, succeeds.
    v2_zip = _zip_bytes("v2")
    v2_signed = _sign(ctx, signer, s3, bucket, "payload-v2", v2_zip, allowed_profile["profileName"])
    lam.update_function_code(FunctionName=fn["name"], ZipFile=v2_signed)
    settled = _wait_settled(lam, fn["name"])
    assert settled["LastUpdateStatus"] == "Successful", (
        f"positive control: correctly-signed update did not succeed: "
        f"{settled.get('LastUpdateStatus')!r} {settled.get('LastUpdateStatusReason')!r}"
    )
    v2_sha = settled["CodeSha256"]
    assert v2_sha == _code_sha256(v2_signed), (
        f"positive control: CodeSha256 {v2_sha!r} does not match the deployed bytes' own hash"
    )
    assert _invoke_body(lam, fn["name"]) == {"marker": "v2"}, (
        "positive control: the function is not running the code it was just signed and deployed with"
    )

    # Signed by a profile not in the config; unsigned code would instead raise the different
    # InvalidCodeSignatureException, so a signed-but-mismatched package is needed here.
    v3_zip = _zip_bytes("v3")
    v3_mismatch_signed = _sign(
        ctx, signer, s3, bucket, "payload-v3-mismatch", v3_zip, mismatch_profile["profileName"]
    )
    error_code, error_message = _reject(lambda: lam.update_function_code(FunctionName=fn["name"], ZipFile=v3_mismatch_signed))
    assert error_code == "CodeVerificationFailedException", (
        f"expected CodeVerificationFailedException, got {error_code!r}"
    )
    assert error_message == (
        "Lambda cannot deploy the function. The function or layer might be signed using a "
        "signature that the client is not configured to accept. Check the provided signature "
        f"for {fn['arn']}."
    ), f"unexpected signature-mismatch message, got {error_message!r}"

    # Independent reads show the rejected package was never stored.
    after_reject = lam.get_function_configuration(FunctionName=fn["name"])
    assert after_reject["CodeSha256"] == v2_sha, (
        f"CodeSha256 changed from {v2_sha!r} to {after_reject['CodeSha256']!r} despite the refusal "
        f"-- the rejected package was stored anyway"
    )
    assert _invoke_body(lam, fn["name"]) == {"marker": "v2"}, (
        "the function is executing code other than what it ran before the rejected deployment"
    )

    # The same source payload signed by the allowed profile succeeds: the refusal was the signer.
    v3_allowed_signed = _sign(
        ctx, signer, s3, bucket, "payload-v3-allowed", v3_zip, allowed_profile["profileName"]
    )
    lam.update_function_code(FunctionName=fn["name"], ZipFile=v3_allowed_signed)
    restored = _wait_settled(lam, fn["name"])
    assert restored["LastUpdateStatus"] == "Successful", (
        f"restore: correctly-signed identical payload did not succeed: "
        f"{restored.get('LastUpdateStatus')!r} {restored.get('LastUpdateStatusReason')!r}"
    )
    assert restored["CodeSha256"] == _code_sha256(v3_allowed_signed), (
        f"restore: CodeSha256 {restored['CodeSha256']!r} does not match the deployed bytes' own hash"
    )
    assert _invoke_body(lam, fn["name"]) == {"marker": "v3"}, (
        "restore: the function is not running the payload that was refused under the wrong signer "
        "and just accepted under the right one"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CodeSigningConfigNotFoundException",
            "ResourceNotFoundException",
        ):
            raise


def _reject(call):
    """The AWS error (code, message) for a call that must fail; an unexpected success raises."""
    try:
        result = call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected the call to be refused for a signature mismatch, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _code_sha256(zip_bytes: bytes) -> str:
    """Lambda's own recipe for CodeSha256: base64(sha256(deployment package))."""
    return base64.b64encode(hashlib.sha256(zip_bytes).digest()).decode()


def _zip_bytes(marker: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            f"def handler(event, context):\n    return {{'marker': {marker!r}}}\n",
        )
    return buf.getvalue()


def _minimal_zip_bytes() -> bytes:
    return _zip_bytes("v1")


def _invoke_body(lam, name):
    resp = lam.invoke(FunctionName=name, Payload=b"{}")
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{name}: StatusCode {resp['StatusCode']!r} {raw!r}"
    assert "FunctionError" not in resp, (
        f"{name} invocation failed with FunctionError={resp.get('FunctionError')!r}: {raw!r}"
    )
    return json.loads(raw)


def _sign(ctx, signer, s3, bucket, label, zip_bytes, profile_name):
    src_key = f"unsigned/{label}.zip"
    put_resp = s3.put_object(Bucket=bucket, Key=src_key, Body=zip_bytes)
    job = signer.start_signing_job(
        source={"s3": {"bucketName": bucket, "key": src_key, "version": put_resp["VersionId"]}},
        destination={"s3": {"bucketName": bucket, "prefix": f"signed/{label}/"}},
        profileName=profile_name,
    )
    signed_key = _wait_for_signing_job(signer, job["jobId"])
    return s3.get_object(Bucket=bucket, Key=signed_key)["Body"].read()


def _put_signing_profile(ctx, signer):
    name = ctx.unique_name("sim2realbehavsp").replace("-", "")[:64]
    resp = signer.put_signing_profile(
        profileName=name,
        platformId="AWSLambda-SHA384-ECDSA",
        tags={"sim2real": "update-function-code-invalid-signature-rejected"},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    return {"profileName": name, "profileVersionArn": resp["profileVersionArn"]}


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-csc-")[:63].lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_for_signing_job(signer, job_id, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = signer.describe_signing_job(jobId=job_id)
        status = job["status"]
        if status == "Succeeded":
            return job["signedObject"]["s3"]["key"]
        if status == "Failed":
            raise AssertionError(f"signing job failed: {job.get('statusReason')}")
        time.sleep(interval_s)
    raise AssertionError("signing job did not complete in time")


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg.get('StateReason')}")
        time.sleep(2)
    raise AssertionError("function did not become Active in time")


def _wait_settled(lam, name, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Failed":
            raise AssertionError(f"{name} entered State=Failed: {cfg.get('StateReason')}")
        if cfg.get("LastUpdateStatus") == "Failed":
            return cfg
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        time.sleep(interval_s)
    raise AssertionError(f"{name} did not settle within {timeout_s}s")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
        Tags={"sim2real": "update-function-code-invalid-signature-rejected"},
    )
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(lam, name)
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
