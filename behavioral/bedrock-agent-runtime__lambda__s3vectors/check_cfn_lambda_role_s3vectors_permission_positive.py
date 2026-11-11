"""cfn-lambda-role-s3vectors-permission-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-lambda-role-s3vectors-permission-positive"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

_VECTOR_CODE = """
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    bucket = os.environ["VECTOR_BUCKET"]
    index = os.environ["VECTOR_INDEX"]
    error_code = None
    data = None
    try:
        client = boto3.client("s3vectors")
        client.put_vectors(
            vectorBucketName=bucket,
            indexName=index,
            vectors=[
                {
                    "key": "lambda-key-1",
                    "data": {"float32": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]},
                }
            ],
        )
        resp = client.get_vectors(
            vectorBucketName=bucket,
            indexName=index,
            keys=["lambda-key-1"],
            returnData=True,
        )
        vectors = resp.get("vectors", [])
        if vectors:
            data = vectors[0]["data"]["float32"]
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
    except Exception as e:
        error_code = "__unexpected__:" + type(e).__name__ + ":" + str(e)
    return {"errorCode": error_code, "data": data}
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed policy scoped to the real vector index ARN lets the Lambda's PutVectors +
    GetVectors data-plane round-trip succeed end-to-end: the written vector is read back with
    the expected float32 values."""
    s3v = ctx.client("s3vectors")
    bucket_name = _xname(ctx, "vb")
    index_name = _xname(ctx, "idx")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

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

    index_arn = f"arn:aws:s3vectors:{region}:{account}:bucket/{bucket_name}/index/{index_name}"
    template = _template(index_arn, bucket_name, index_name)
    result = _deploy_cfn(ctx, template)
    function_name = result["outputs"]["FunctionName"]
    _wait_function_active(ctx, function_name)

    payload = _invoke_json(ctx, function_name)
    if isinstance(payload["errorCode"], str) and payload["errorCode"].startswith(
        "__unexpected__:UnknownServiceError"
    ):
        raise AssertionError(
            "Lambda runtime's bundled boto3/botocore predates s3vectors support: "
            f"{payload['errorCode']}"
        )
    assert payload["errorCode"] is None, payload
    got = payload["data"]
    expected = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    assert got is not None and len(got) == len(expected), (got, expected)
    for actual, want in zip(got, expected):
        assert abs(actual - want) < 1e-3, (got, expected)


def _template(index_arn: str, bucket_name: str, index_name: str) -> str:
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
                                "PolicyName": "AllowVectorOps",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3vectors:PutVectors",
                                                "s3vectors:GetVectors",
                                            ],
                                            "Resource": index_arn,
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
                        "Environment": {
                            "Variables": {
                                "VECTOR_BUCKET": bucket_name,
                                "VECTOR_INDEX": index_name,
                            }
                        },
                        "Code": {"ZipFile": _VECTOR_CODE},
                    },
                },
            },
            "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
        }
    )


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


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
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
