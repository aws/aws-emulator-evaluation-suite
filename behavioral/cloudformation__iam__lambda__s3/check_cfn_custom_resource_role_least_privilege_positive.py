"""cfn-custom-resource-role-least-privilege-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-resource-role-least-privilege-positive"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A custom-resource Lambda role scoped only to s3:PutObject on one bucket writes the v1 object on
    stack CREATE and the v2 object on a stack UPDATE, with the v1 object unchanged, so the scoped
    policy suffices for both lifecycle events."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx)

    role_arn = _create_lambda_role(
        ctx,
        extra_statements=[
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"}
        ],
    )
    fn_arn = _create_lambda_function(ctx, role_arn)

    key_v1 = "cr-object.txt"
    stack_name = _xname(ctx, "stk")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_cr_template(fn_arn, bucket, key_v1, "least-privilege-write-v1"),
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    create_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"stack {stack_name} create terminal",
    )
    assert create_status == "CREATE_COMPLETE", f"create ended in {create_status}"
    body_v1_after_create = s3.get_object(Bucket=bucket, Key=key_v1)["Body"].read().decode("utf-8")
    assert body_v1_after_create == "least-privilege-write-v1", (
        f"expected 'least-privilege-write-v1', got {body_v1_after_create!r}"
    )

    # Drive a real UPDATE transition: change the object key/body the custom resource writes.
    key_v2 = "cr-object-v2.txt"
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_cr_template(fn_arn, bucket, key_v2, "least-privilege-write-v2"),
    )
    update_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"stack {stack_name} update terminal",
    )
    assert update_status == "UPDATE_COMPLETE", f"update ended in {update_status}"
    body_v2 = s3.get_object(Bucket=bucket, Key=key_v2)["Body"].read().decode("utf-8")
    assert body_v2 == "least-privilege-write-v2", (
        f"expected 'least-privilege-write-v2', got {body_v2!r}"
    )
    # The v1 object still exists too (the update didn't recreate the custom resource).
    body_v1_after_update = s3.get_object(Bucket=bucket, Key=key_v1)["Body"].read().decode("utf-8")
    assert body_v1_after_update == "least-privilege-write-v1", (
        f"expected 'least-privilege-write-v1' to survive the update, got {body_v1_after_update!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bucket")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 is the one region S3 rejects a LocationConstraint for
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    to_delete: list[dict[str, str]] = []
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for m in page.get("DeleteMarkers", []):
            to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
    for i in range(0, len(to_delete), 1000):
        batch = to_delete[i : i + 1000]
        if batch:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


_CR_HANDLER_SOURCE = '''
import json
import boto3
import urllib3

_http = urllib3.PoolManager()


def handler(event, context):
    request_type = event.get("RequestType")
    props = event.get("ResourceProperties", {})
    bucket = props.get("BucketName")
    key = props.get("ObjectKey", "custom-resource-object")
    body_text = props.get("Body", "hello-from-custom-resource")
    physical_id = event.get("PhysicalResourceId") or key
    response = {
        "PhysicalResourceId": physical_id,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": {},
    }
    try:
        if request_type in ("Create", "Update"):
            s3 = boto3.client("s3")
            s3.put_object(Bucket=bucket, Key=key, Body=body_text.encode("utf-8"))
        response["Status"] = "SUCCESS"
    except Exception as exc:  # noqa: BLE001
        response["Status"] = "FAILED"
        response["Reason"] = str(exc)[:400]
    encoded = json.dumps(response).encode("utf-8")
    _http.request("PUT", event["ResponseURL"], body=encoded, headers={"Content-Type": ""})
'''


def _zip_lambda_code(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_source)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + extra_statements
    policy_name = _xname(ctx, "policy")
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    zip_bytes = _zip_lambda_code(_CR_HANDLER_SOURCE)
    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags=_xsvc_resource_tags(),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s in {"Active", "Failed"},
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} active",
    )
    return resp["FunctionArn"]


def _cr_template(function_arn: str, bucket: str, key: str, body: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Writer": {
                    "Type": "Custom::S3Writer",
                    "Properties": {
                        "ServiceToken": function_arn,
                        "BucketName": bucket,
                        "ObjectKey": key,
                        "Body": body,
                    },
                }
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
