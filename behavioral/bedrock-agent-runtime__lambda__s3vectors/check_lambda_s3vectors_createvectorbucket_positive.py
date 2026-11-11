"""lambda-s3vectors-createvectorbucket-positive."""
from __future__ import annotations

import importlib
import io
import json
import os
import re
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-s3vectors-createvectorbucket-positive"
GROUP = "arn-resolution"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_BUCKET_ARN_RE = re.compile(
    r"^arn:aws[-a-z0-9]*:s3vectors:[a-z0-9-]+:\d{12}:bucket/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateVectorBucket from a Lambda returns the bucket's ARN, and CreateIndex with only that
    vectorBucketArn creates the index, which is the bucket's only listed index."""
    role_arn = _create_role(ctx, [{"Effect": "Allow", "Action": "s3vectors:*", "Resource": "*"}])
    fn_name = _create_dispatcher_lambda(ctx, role_arn)
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-bkt-")
    create_body = _invoke_ok(
        ctx,
        fn_name,
        "create_vector_bucket",
        {"vectorBucketName": bucket_name, "tags": {"sim2real:managed": "true"}},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket_arn = create_body["result"]["vectorBucketArn"]
    assert _BUCKET_ARN_RE.match(bucket_arn), f"unexpected vectorBucketArn shape: {bucket_arn}"
    assert bucket_arn.endswith(f"bucket/{bucket_name}")

    index_name = ctx.unique_name("sim2real-s3v-idx-")
    index_body = _invoke_ok(
        ctx,
        fn_name,
        "create_index",
        {
            "vectorBucketArn": bucket_arn,
            "indexName": index_name,
            "dataType": "float32",
            "dimension": 3,
            "distanceMetric": "cosine",
            "tags": {"sim2real:managed": "true"},
        },
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    assert index_body["ok"] is True
    assert index_body["result"]["indexArn"].endswith(f"bucket/{bucket_name}/index/{index_name}")

    # Confirm, from the account's own view of the bucket, that the index the Lambda
    # created via the bucket ARN really landed inside that same bucket.
    deadline = time.monotonic() + 30.0
    listed_names: set[str] = set()
    while time.monotonic() < deadline:
        listed_names = {i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket_name)["indexes"]}
        if listed_names == {index_name}:
            break
        time.sleep(2)
    assert listed_names == {index_name}


_HANDLER_CODE = '''
import boto3
import json


def handler(event, context):
    client = boto3.client("s3vectors")
    action = event["action"]
    params = event.get("params", {})
    method = getattr(client, action)
    try:
        result = method(**params)
        result.pop("ResponseMetadata", None)
        safe = json.loads(json.dumps(result, default=str))
        return {"ok": True, "result": safe}
    except Exception as exc:
        resp = getattr(exc, "response", None)
        code = resp["Error"]["Code"] if resp and "Error" in resp else type(exc).__name__
        return {"ok": False, "code": code, "message": str(exc)}
'''

_ALLOWED_BOTOCORE_DATA_SERVICES = {"s3vectors"}
_BUNDLE_MODULES = ("boto3", "botocore")


def _add_module_to_zip(zf: zipfile.ZipFile, module_name: str) -> None:
    mod = importlib.import_module(module_name)
    mod_path = getattr(mod, "__path__", None)
    if not mod_path:
        zf.write(mod.__file__, arcname=os.path.basename(mod.__file__))
        return
    pkg_dir = mod_path[0]
    root_dir = os.path.dirname(pkg_dir)
    data_dir = os.path.join(pkg_dir, "data")
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if dirpath == data_dir:
            dirnames[:] = [d for d in dirnames if d in _ALLOWED_BOTOCORE_DATA_SERVICES]
        for fname in filenames:
            if fname.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(dirpath, fname)
            arc = os.path.relpath(full, root_dir)
            zf.write(full, arcname=arc)


def _build_deployment_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER_CODE)
        for name in _BUNDLE_MODULES:
            _add_module_to_zip(zf, name)
    return buf.getvalue()


def _create_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-s3v-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=name, PolicyName="inline-s3vectors", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline-s3vectors"))
    return role_arn


def _create_dispatcher_lambda(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-s3v-fn-")
    code = _build_deployment_zip()
    deadline = time.monotonic() + 60.0
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                MemorySize=256,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 60.0
    while True:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            break
        if state == "Failed" or time.monotonic() > deadline:
            raise AssertionError(f"lambda function never became Active (state={state})")
        time.sleep(2)
    return name


def _invoke(ctx, function_name: str, action: str, params: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"action": action, "params": params}).encode("utf-8"),
    )
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised: {resp['Payload'].read().decode()}")
    return json.loads(resp["Payload"].read())


def _invoke_ok(ctx, function_name: str, action: str, params: dict[str, Any], timeout_s: float = 45.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        body = _invoke(ctx, function_name, action, params)
        if body.get("ok"):
            return body
        last = body
        if body.get("code") not in ("AccessDeniedException", "ServiceUnavailableException", "InternalServerException"):
            raise AssertionError(f"unexpected failure for {action}: {body}")
        time.sleep(2)
    raise AssertionError(f"{action} never succeeded, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
