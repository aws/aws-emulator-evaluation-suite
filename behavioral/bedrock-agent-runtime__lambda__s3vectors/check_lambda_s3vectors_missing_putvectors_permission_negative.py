"""lambda-s3vectors-missing-putvectors-permission-negative."""
from __future__ import annotations

import importlib
import io
import json
import os
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-s3vectors-missing-putvectors-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role granted GetVectors but not PutVectors gets AccessDeniedException from PutVectors and
    writes nothing, while its GetVectors call returns the seed vector."""
    setup = _create_bucket_and_index(ctx, dimension=2)
    s3v = ctx.client("s3vectors")
    s3v.put_vectors(
        vectorBucketName=setup["bucket_name"],
        indexName=setup["index_name"],
        vectors=[{"key": "seed", "data": {"float32": [9.0, 9.0]}}],
    )

    role_arn = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": ["s3vectors:GetVectors", "s3vectors:ListVectors"], "Resource": "*"}],
    )
    fn_name = _create_dispatcher_lambda(ctx, role_arn)

    denied_body = _invoke_ok_or_denied(
        ctx,
        fn_name,
        "put_vectors",
        {
            "vectorBucketName": setup["bucket_name"],
            "indexName": setup["index_name"],
            "vectors": [{"key": "unauthorized", "data": {"float32": [1.0, 2.0]}}],
        },
    )
    assert denied_body["ok"] is False, (
        f"expected the put_vectors call from a role without s3vectors:PutVectors to fail, "
        f"got ok=True body={denied_body}"
    )
    assert denied_body["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for the missing s3vectors:PutVectors permission, "
        f"got {denied_body['code']!r}"
    )

    # (b) the effect is absent: the vector the denied call tried to write never landed.
    survivors = s3v.get_vectors(
        vectorBucketName=setup["bucket_name"],
        indexName=setup["index_name"],
        keys=["unauthorized"],
        returnData=True,
    )["vectors"]
    assert survivors == [], (
        f"the denied write must not have persisted a vector, but get_vectors returned {survivors!r}"
    )

    # (c) positive control: the same role/function CAN read, proving the denial above
    # is specific to the missing PutVectors permission and not a broken setup.
    control_body = _invoke_ok(
        ctx,
        fn_name,
        "get_vectors",
        {
            "vectorBucketName": setup["bucket_name"],
            "indexName": setup["index_name"],
            "keys": ["seed"],
            "returnData": True,
        },
    )
    seeds = control_body["result"]["vectors"]
    assert len(seeds) == 1, (
        f"positive control get_vectors (authorized) should return exactly the seed vector, "
        f"got {seeds!r}"
    )
    assert seeds[0]["key"] == "seed", (
        f"positive control get_vectors should return the seed vector, got key={seeds[0].get('key')!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                Tags={"sim2real": CHECK},
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
    # IAM's deny-by-default behaves correctly the instant the role has no matching
    # allow, so no propagation grace period is needed for a denial itself. But a
    # transient ServiceUnavailable/Internal error from the still-warming Lambda/network
    # path should not be mistaken for the AccessDeniedException we are testing for.
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
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name, tags={"sim2real": CHECK}
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    index_name = ctx.unique_name("sim2real-s3v-idx-")
    index_arn = s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric=distance_metric,
        tags={"sim2real": CHECK},
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
