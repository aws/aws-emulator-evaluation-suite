"""lambda-s3vectors-missing-queryvectors-permission-negative."""
from __future__ import annotations

import importlib
import io
import json
import os
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-s3vectors-missing-queryvectors-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without s3vectors:QueryVectors gets AccessDeniedException and no result, while its
    GetVectors call succeeds; once QueryVectors is granted, the same query returns the anchor vector."""
    setup = _create_bucket_and_index(ctx, dimension=2, distance_metric="euclidean")
    s3v = ctx.client("s3vectors")
    s3v.put_vectors(
        vectorBucketName=setup["bucket_name"],
        indexName=setup["index_name"],
        vectors=[{"key": "anchor", "data": {"float32": [4.0, 4.0]}}],
    )

    iam = ctx.client("iam")
    role_arn, role_name = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["s3vectors:PutVectors", "s3vectors:GetVectors"], "Resource": "*"}],
    )
    fn_name = _create_dispatcher_lambda(ctx, role_arn)

    query_params = {
        "vectorBucketName": setup["bucket_name"],
        "indexName": setup["index_name"],
        "queryVector": {"float32": [4.0, 4.0]},
        "topK": 1,
    }
    denied_body = _invoke_ok_or_denied(ctx, fn_name, "query_vectors", query_params)
    assert denied_body["ok"] is False, f"expected QueryVectors to be denied, got {denied_body}"
    assert denied_body["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got code={denied_body.get('code')} body={denied_body}"
    )
    # (b) the effect is absent: no result/query matches were ever produced.
    assert "result" not in denied_body, f"denied call must not carry a result, got {denied_body}"

    # (c) positive control: the same role/function CAN read via GetVectors, ruling out
    # a broken role/function rather than a permission-specific denial.
    control_body = _invoke_ok(
        ctx,
        fn_name,
        "get_vectors",
        {
            "vectorBucketName": setup["bucket_name"],
            "indexName": setup["index_name"],
            "keys": ["anchor"],
            "returnData": True,
        },
    )
    anchors = control_body["result"]["vectors"]
    assert len(anchors) == 1, f"expected exactly one vector from GetVectors, got {anchors}"
    assert anchors[0]["key"] == "anchor", f"expected key 'anchor', got {anchors[0]}"

    # (d) restore: grant the missing permission on the identical role/function and
    # demand the identical QueryVectors call now succeeds, returning the correct
    # nearest match — proving the earlier denial was specific to QueryVectors.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline-s3vectors",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3vectors:PutVectors", "s3vectors:GetVectors", "s3vectors:QueryVectors"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    restored_body = _invoke_ok(ctx, fn_name, "query_vectors", {**query_params, "returnDistance": True})
    matches = restored_body["result"]["vectors"]
    assert len(matches) == 1, f"expected exactly one match after granting QueryVectors, got {matches}"
    assert matches[0]["key"] == "anchor", f"expected nearest match 'anchor', got {matches[0]}"
    assert matches[0]["distance"] < 1e-6, f"expected ~0 distance for an exact query match, got {matches[0]}"


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


def _create_role(ctx, statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-s3v-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=name, PolicyName="inline-s3vectors", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline-s3vectors"))
    return role_arn, name


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


def _invoke_ok_or_denied(ctx, function_name: str, action: str, params: dict[str, Any], timeout_s: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        body = _invoke(ctx, function_name, action, params)
        if body.get("ok") is False and body.get("code") == "AccessDeniedException":
            return body
        last = body
        if body.get("code") not in ("ServiceUnavailableException", "InternalServerException"):
            return body
        time.sleep(2)
    raise AssertionError(f"{action} never reached a stable outcome, last={last}")


def _create_bucket_and_index(ctx, dimension: int, distance_metric: str = "cosine") -> dict[str, str]:
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-bkt-")
    bucket_arn = s3v.create_vector_bucket(vectorBucketName=bucket_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    index_name = ctx.unique_name("sim2real-s3v-idx-")
    index_arn = s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric=distance_metric,
    )["indexArn"]
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    return {
        "bucket_name": bucket_name,
        "bucket_arn": bucket_arn,
        "index_name": index_name,
        "index_arn": index_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
