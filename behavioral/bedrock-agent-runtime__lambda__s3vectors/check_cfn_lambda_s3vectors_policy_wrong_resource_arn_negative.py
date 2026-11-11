"""cfn-lambda-s3vectors-policy-wrong-resource-arn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-lambda-s3vectors-policy-wrong-resource-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_VECTOR_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    error_code = None
    try:
        client = boto3.client("s3vectors")
        client.put_vectors(
            vectorBucketName=event["vectorBucketName"],
            indexName=event["indexName"],
            vectors=[{"key": event["key"], "data": {"float32": [0.3] * 8}}],
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
    except Exception as e:
        error_code = "__unexpected__:" + type(e).__name__ + ":" + str(e)
    return {"errorCode": error_code}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutVectors policy scoped to a decoy index denies (AccessDeniedException) writes to the real
    index, which stays without the vector, while the same function writes to the decoy index."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    target_bucket, target_index = _create_bucket_and_index(ctx, s3v, "target")
    decoy_bucket, decoy_index = _create_bucket_and_index(ctx, s3v, "decoy")
    decoy_index_arn = (
        f"arn:aws:s3vectors:{region}:{account}:bucket/{decoy_bucket}/index/{decoy_index}"
    )

    template = _template(decoy_index_arn)
    result = _deploy_cfn(ctx, template, teardown_deadline)
    function_name = result["outputs"]["FunctionName"]
    _wait_function_active(ctx, function_name)

    target_key = "target-key"
    denied_payload = _invoke_json(
        ctx,
        function_name,
        {"vectorBucketName": target_bucket, "indexName": target_index, "key": target_key},
    )
    denied_code = denied_payload["errorCode"]
    if isinstance(denied_code, str) and denied_code.startswith(
        "__unexpected__:UnknownServiceError"
    ):
        raise AssertionError(
            f"Lambda runtime's bundled boto3/botocore predates s3vectors support: {denied_code}"
        )
    assert denied_code == "AccessDeniedException", denied_payload

    decoy_key = "decoy-key"
    allowed_payload = _invoke_json(
        ctx,
        function_name,
        {"vectorBucketName": decoy_bucket, "indexName": decoy_index, "key": decoy_key},
    )
    assert allowed_payload["errorCode"] is None, allowed_payload

    target_keys = _list_vector_keys(ctx, target_bucket, target_index)
    assert target_key not in target_keys, target_keys

    decoy_keys = _list_vector_keys(ctx, decoy_bucket, decoy_index)
    assert decoy_key in decoy_keys, decoy_keys


def _create_bucket_and_index(ctx, s3v, kind: str) -> tuple[str, str]:
    bucket_name = _xname(ctx, f"vb-{kind}")
    index_name = _xname(ctx, f"idx-{kind}")
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags=_xsvc_resource_tags())
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=8,
        distanceMetric="cosine",
        tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(
        lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    )
    return bucket_name, index_name


def _template(decoy_index_arn: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        ],
                        "Policies": [
                            {
                                "PolicyName": "AllowPutVectorsOnDecoyOnly",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "s3vectors:PutVectors",
                                            "Resource": decoy_index_arn,
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Timeout": 30,
                        "Code": {"ZipFile": _VECTOR_CODE},
                    },
                },
            },
            "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
        }
    )


def _list_vector_keys(ctx, bucket_name: str, index_name: str) -> set[str]:
    s3v = ctx.client("s3vectors")
    keys: set[str] = set()
    token = None
    while True:
        kwargs = {"vectorBucketName": bucket_name, "indexName": index_name}
        if token:
            kwargs["nextToken"] = token
        resp = s3v.list_vectors(**kwargs)
        keys.update(v["key"] for v in resp.get("vectors", []))
        token = resp.get("nextToken")
        if not token:
            break
    return keys


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


#: The suite's cleanup budget; the stack teardowns of one run share one deadline inside it.
_CLEANUP_BUDGET_S = 900.0


def _delete_stack_and_wait(ctx, stack_name: str, teardown_deadline) -> None:
    """Delete the stack and poll every 2 s until it is gone, to the run's cleanup deadline;
    DELETE_FAILED raises at once."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _CLEANUP_BUDGET_S)
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} at the cleanup deadline")
        time.sleep(2)


def _deploy_cfn(
    ctx,
    template,
    teardown_deadline,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, teardown_deadline))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _wait_function_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    state = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"lambda {function_name} Active",
    )
    if state != "Active":
        raise AssertionError(f"function {function_name} ended in state {state}")


def _invoke_json(ctx, function_name: str, payload: dict | None = None) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    assert resp["StatusCode"] == 200, resp
    body = resp["Payload"].read()
    if "FunctionError" in resp:
        raise AssertionError(f"function error: {body!r}")
    return json.loads(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
