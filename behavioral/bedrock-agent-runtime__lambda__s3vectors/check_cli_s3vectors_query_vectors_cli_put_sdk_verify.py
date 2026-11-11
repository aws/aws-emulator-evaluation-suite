"""cli-s3vectors-query-vectors-cli-put-sdk-verify."""
from __future__ import annotations

import json
import os
import struct
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-s3vectors-query-vectors-cli-put-sdk-verify"
GROUP = "sdk-cli-interop"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Doubles written with CLI put-vectors are stored cast to float32, as read back from a Lambda.

    QueryVectors finds it; GetVectors returns float32-rounded values, not the raw doubles."""
    require_tools("aws")

    bucket_name = ctx.unique_name("sim2real-precision-vb-")
    index_name = ctx.unique_name("sim2real-precision-idx-")

    _run_aws(
        ctx, "s3vectors", "create-vector-bucket",
        "--vector-bucket-name", bucket_name,
        "--tags", "sim2real:managed=true",
    )
    ctx.on_cleanup(lambda: ctx.client("s3vectors").delete_vector_bucket(vectorBucketName=bucket_name))
    _run_aws(
        ctx, "s3vectors", "create-index",
        "--vector-bucket-name", bucket_name,
        "--index-name", index_name,
        "--data-type", "float32",
        "--dimension", "3",
        "--distance-metric", "cosine",
        "--tags", "sim2real:managed=true",
    )
    ctx.on_cleanup(lambda: ctx.client("s3vectors").delete_index(vectorBucketName=bucket_name, indexName=index_name))

    # Doubles with no exact float32 representation.
    raw_values = [0.1, 0.2, 1.0 / 3.0]
    expected_f32 = [_to_float32(v) for v in raw_values]

    vectors = [{"key": "precision-vec", "data": {"float32": raw_values}, "metadata": {"note": "precision"}}]
    vectors_path = _write_temp_json(vectors)
    try:
        _run_aws(
            ctx, "s3vectors", "put-vectors",
            "--vector-bucket-name", bucket_name,
            "--index-name", index_name,
            "--vectors", f"file://{vectors_path}",
        )
    finally:
        os.unlink(vectors_path)

    handler_source = (
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    client = boto3.client('s3vectors')\n"
        "    resp = client.query_vectors(\n"
        "        vectorBucketName=event['bucket'],\n"
        "        indexName=event['index'],\n"
        "        queryVector={'float32': event['queryVector']},\n"
        "        topK=1,\n"
        "        returnMetadata=True,\n"
        "        returnDistance=True,\n"
        "    )\n"
        "    stored = client.get_vectors(\n"
        "        vectorBucketName=event['bucket'],\n"
        "        indexName=event['index'],\n"
        "        keys=[event['vectorKey']],\n"
        "        returnData=True,\n"
        "    )\n"
        "    return {'vectors': resp.get('vectors', []), 'stored': stored.get('vectors', [])}\n"
    )
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    index_arn = f"arn:aws:s3vectors:{ctx.region}:{account_id}:bucket/{bucket_name}/index/{index_name}"
    query_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3vectors:QueryVectors", "s3vectors:GetIndex", "s3vectors:GetVectors"], "Resource": index_arn}],
    }
    role_arn = _create_lambda_execution_role(ctx, inline_policies={"s3vectors-query": query_policy})
    function_name = ctx.unique_name("sim2real-precision-fn-")
    _create_function_cli(ctx, function_name, role_arn, handler_source)

    # Query with the expected float32 values so the written vector is its own nearest neighbor.
    lam = ctx.client("lambda")
    payload = {"bucket": bucket_name, "index": index_name, "queryVector": expected_f32, "vectorKey": "precision-vec"}
    deadline = time.monotonic() + 30.0
    result_vectors: list = []
    stored_vectors: list = []
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode())
        assert "FunctionError" not in resp, f"lambda invocation errored: {resp}"
        body = json.loads(resp["Payload"].read())
        result_vectors = body.get("vectors", [])
        stored_vectors = body.get("stored", [])
        if result_vectors and result_vectors[0].get("key") == "precision-vec":
            break
        time.sleep(3)

    assert result_vectors, "QueryVectors (via Lambda SDK) never returned any results"
    top = result_vectors[0]
    assert top["key"] == "precision-vec", f"expected nearest neighbor key 'precision-vec', got {top.get('key')!r}"
    assert top["metadata"]["note"] == "precision", f"expected metadata note 'precision', got {top.get('metadata')!r}"
    # Service-side float32 cosine arithmetic adds rounding error, hence the loose 1e-3 bound.
    assert top["distance"] < 1e-3, f"expected near-zero cosine distance to its own float32-cast vector, got {top['distance']}"

    # Distance cannot tell a float32 cast from a double echo (~1e-16 apart), so compare the stored
    # components directly against both the float32 cast and the raw double.
    assert stored_vectors, "GetVectors (via Lambda SDK) never returned the stored vector"
    stored = stored_vectors[0]
    assert stored["key"] == "precision-vec", f"expected stored key 'precision-vec', got {stored.get('key')!r}"
    got_components = list(stored["data"]["float32"])
    assert len(got_components) == len(expected_f32), (
        f"expected {len(expected_f32)} components, got {len(got_components)}: {got_components!r}"
    )
    for i, (raw_v, exp_v, got_v) in enumerate(zip(raw_values, expected_f32, got_components)):
        assert got_v == exp_v, (
            f"component {i}: stored value does not match the float32-cast of the input; "
            f"expected {exp_v!r} (float32 cast of {raw_v!r}), got {got_v!r}"
        )
        assert got_v != raw_v, (
            f"component {i}: stored value {got_v!r} is a raw double echo of the input {raw_v!r} "
            f"-- the service did not perform the documented float32 cast"
        )


def _to_float32(x: float) -> float:
    return struct.unpack("f", struct.pack("f", x))[0]


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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


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


def _write_temp_json(data) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        return f.name


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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
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
            "--tags", "sim2real:managed=true",
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
