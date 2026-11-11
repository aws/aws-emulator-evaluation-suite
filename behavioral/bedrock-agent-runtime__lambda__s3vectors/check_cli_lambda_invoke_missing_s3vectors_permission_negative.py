"""cli-lambda-invoke-missing-s3vectors-permission-negative."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-lambda-invoke-missing-s3vectors-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_MANAGED_TAG_KEY = "sim2real:managed"
_TAGS_MAP = {_MANAGED_TAG_KEY: "true", "sim2real:prefix": CHECK}
_TAGS_KV = [{"Key": k, "Value": v} for k, v in _TAGS_MAP.items()]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks the s3vectors grant gets AccessDeniedException from PutVectors and its
    vector is absent, while an identical Lambda with the grant succeeds and its vector is present."""
    require_tools("aws")

    bucket_name = ctx.unique_name("sim2real-negperm-vb-")
    index_name = ctx.unique_name("sim2real-negperm-idx-")

    s3v = ctx.client("s3vectors")
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags=_TAGS_MAP)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name, indexName=index_name, dataType="float32", dimension=3,
        distanceMetric="cosine", tags=_TAGS_MAP,
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    index_arn = f"arn:aws:s3vectors:{ctx.region}:{account_id}:bucket/{bucket_name}/index/{index_name}"

    handler_source = (
        "import boto3\n"
        "from botocore.exceptions import ClientError\n\n"
        "def handler(event, context):\n"
        "    client = boto3.client('s3vectors')\n"
        "    try:\n"
        "        client.put_vectors(\n"
        "            vectorBucketName=event['bucket'],\n"
        "            indexName=event['index'],\n"
        "            vectors=[{'key': event['key'], 'data': {'float32': event['vector']}}],\n"
        "        )\n"
        "        return {'ok': True}\n"
        "    except ClientError as e:\n"
        "        return {'ok': False, 'code': e.response['Error']['Code']}\n"
    )

    # --- role WITHOUT s3vectors permission (basic execution only) ---
    role_without_perm = _create_lambda_execution_role(ctx)
    fn_negative = ctx.unique_name("sim2real-negperm-fn-")
    _create_function_cli(ctx, fn_negative, role_without_perm, handler_source)

    # --- second role WITH s3vectors:PutVectors on the same index (positive control) ---
    put_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3vectors:PutVectors", "Resource": index_arn}],
    }
    role_with_perm = _create_lambda_execution_role(ctx, inline_policies={"s3vectors-put": put_policy})
    fn_positive = ctx.unique_name("sim2real-posperm-fn-")
    _create_function_cli(ctx, fn_positive, role_with_perm, handler_source)

    lam = ctx.client("lambda")

    neg_payload = {"bucket": bucket_name, "index": index_name, "key": "neg-vec", "vector": [0.1, 0.2, 0.3]}
    neg_resp = lam.invoke(FunctionName=fn_negative, Payload=json.dumps(neg_payload).encode())
    assert "FunctionError" not in neg_resp, f"unexpected Lambda runtime crash: {neg_resp}"
    neg_body = json.loads(neg_resp["Payload"].read())
    assert neg_body["ok"] is False, "expected the permission-less Lambda's PutVectors call to fail"
    assert neg_body["code"] == "AccessDeniedException", f"expected AccessDeniedException, got {neg_body['code']!r}"

    pos_payload = {"bucket": bucket_name, "index": index_name, "key": "pos-vec", "vector": [0.9, 0.8, 0.7]}
    pos_resp = lam.invoke(FunctionName=fn_positive, Payload=json.dumps(pos_payload).encode())
    assert "FunctionError" not in pos_resp, f"unexpected Lambda runtime crash: {pos_resp}"
    pos_body = json.loads(pos_resp["Payload"].read())
    assert pos_body["ok"] is True, f"positive control unexpectedly failed: {pos_body}"

    # Verify the effect server-side, independently of what the Lambdas reported.
    got = s3v.get_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=["neg-vec", "pos-vec"])
    found_keys = {v["key"] for v in got.get("vectors", [])}
    assert "neg-vec" not in found_keys, "the rejected write must not have persisted a vector"
    assert "pos-vec" in found_keys, "the permitted write must have persisted its vector"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws_retrying(ctx, args, retry_substrings, timeout_s=90.0, poll_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_stderr = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, ["aws", "--output", "json", *args], check=False, timeout_s=30.0)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_stderr = proc.stderr
        if any(s in proc.stderr for s in retry_substrings):
            time.sleep(poll_s)
            continue
        raise AssertionError(f"aws {' '.join(args)} failed: {last_stderr[-500:]}")
    raise AssertionError(f"aws {' '.join(args)} did not succeed within {timeout_s}s: {last_stderr[-500:]}")


def _zip_from_source(handler_source: str, filename: str = "index.py") -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, handler_source)
    return buf.getvalue()


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol_name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_lambda_execution_role(ctx, inline_policies=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV)
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    for pname, pdoc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(pdoc))
    return role_arn


def _create_function_cli(ctx, function_name, role_arn, handler_source, timeout=30, env_vars=None):
    zip_bytes = _zip_from_source(handler_source)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(zip_bytes)
        zip_path = f.name
    try:
        args = [
            "lambda", "create-function",
            "--function-name", function_name,
            "--runtime", "python3.12",
            "--role", role_arn,
            "--handler", "index.handler",
            "--timeout", str(timeout),
            "--zip-file", f"fileb://{zip_path}",
            "--tags", ",".join(f"{k}={v}" for k, v in _TAGS_MAP.items()),
        ]
        if env_vars:
            args += ["--environment", json.dumps({"Variables": env_vars})]
        result = _run_aws_retrying(
            ctx, args,
            retry_substrings=["cannot be assumed", "InvalidParameterValueException", "is not authorized"],
            timeout_s=90.0,
        )
    finally:
        os.unlink(zip_path)
    function_arn = result["FunctionArn"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    _wait_lambda_active(ctx, function_name)
    return function_arn


def _wait_lambda_active(ctx, function_name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=function_name)["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {function_name} never became Active (last state={state})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
