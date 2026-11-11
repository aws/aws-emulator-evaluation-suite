"""lambda-s3vectors-createindex-positive."""
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

CHECK = "lambda-s3vectors-createindex-positive"
GROUP = "arn-resolution"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_INDEX_ARN_RE = re.compile(
    r"^arn:aws[-a-z0-9]*:s3vectors:[a-z0-9-]+:\d{12}:bucket/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
    r"/index/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
)


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function that calls s3vectors:CreateIndex via boto3 gets back an index
    ARN that later resolves correctly on its own (without bucket/index name) for a
    subsequent PutVectors + GetVectors round trip run from the same function."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-bkt-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    index_name = ctx.unique_name("sim2real-s3v-idx-")

    role_arn = _create_role(ctx, [{"Effect": "Allow", "Action": "s3vectors:*", "Resource": "*"}])
    fn_name = _create_dispatcher_lambda(ctx, role_arn)

    create_body = _invoke_ok(
        ctx,
        fn_name,
        "create_index",
        {
            "vectorBucketName": bucket_name,
            "indexName": index_name,
            "dataType": "float32",
            "dimension": 4,
            "distanceMetric": "cosine",
        },
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    index_arn = create_body["result"]["indexArn"]
    assert _INDEX_ARN_RE.match(index_arn), f"unexpected indexArn shape: {index_arn}"
    assert f"bucket/{bucket_name}/index/{index_name}" in index_arn, (
        f"indexArn {index_arn!r} does not embed bucket {bucket_name!r} / index {index_name!r}"
    )

    put_body = _invoke_ok(
        ctx,
        fn_name,
        "put_vectors",
        {"indexArn": index_arn, "vectors": [{"key": "v1", "data": {"float32": [0.5, 0.5, -0.5, -0.5]}}]},
    )
    assert put_body["ok"] is True, f"put_vectors by ARN alone failed: {put_body}"

    get_body = _invoke_ok(
        ctx,
        fn_name,
        "get_vectors",
        {"indexArn": index_arn, "keys": ["v1"], "returnData": True},
    )
    vectors = get_body["result"]["vectors"]
    assert len(vectors) == 1, f"expected exactly 1 vector back, got {vectors}"
    assert vectors[0]["key"] == "v1", f"expected key 'v1', got {vectors[0].get('key')!r}"
    assert vectors[0]["data"]["float32"] == [0.5, 0.5, -0.5, -0.5], (
        f"expected float32 [0.5, 0.5, -0.5, -0.5] back, got {vectors[0]['data'].get('float32')}"
    )


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
