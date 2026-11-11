"""deploy-cfn-role-trusts-s3-service-for-batch-operations."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-role-trusts-s3-service-for-batch-operations"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed IAM role trusting batchoperations.s3.amazonaws.com lets S3 Batch
    Operations actually assume it, invoke a Lambda function per object, and complete the
    job — verified by checking the Lambda-applied object tags, not job status alone."""
    s3 = ctx.client("s3")
    s3control = ctx.client("s3control")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket_name = _xname(ctx, "batchops-bkt")
    code = (
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    s3c = boto3.client('s3')\n"
        "    task = event['tasks'][0]\n"
        "    task_id = task['taskId']\n"
        "    try:\n"
        "        bucket = task['s3BucketArn'].split(':::')[-1]\n"
        "        key = task['s3Key']\n"
        "        s3c.put_object_tagging(\n"
        "            Bucket=bucket, Key=key,\n"
        "            Tagging={'TagSet': [{'Key': 'processed', 'Value': 'true'}]},\n"
        "        )\n"
        "        results = [{'taskId': task_id, 'resultCode': 'Succeeded', 'resultString': 'tagged'}]\n"
        "    except Exception as exc:\n"
        "        results = [{'taskId': task_id, 'resultCode': 'PermanentFailure', 'resultString': str(exc)}]\n"
        "    return {\n"
        "        'invocationSchemaVersion': event['invocationSchemaVersion'],\n"
        "        'treatMissingKeysAs': 'PermanentFailure',\n"
        "        'invocationId': event['invocationId'],\n"
        "        'results': results,\n"
        "    }\n"
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
            "LambdaExecRole": {
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
                            "PolicyName": "tagging",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:PutObjectTagging", "s3:GetObject"],
                                        "Resource": {"Fn::Sub": "arn:aws:s3:::${Bucket}/*"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "TaggerFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": code},
                },
            },
            "BatchOpsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "batchoperations.s3.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "batchops",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:GetBucketLocation"],
                                        "Resource": [
                                            {"Fn::Sub": "arn:aws:s3:::${Bucket}"},
                                            {"Fn::Sub": "arn:aws:s3:::${Bucket}/*"},
                                        ],
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["lambda:InvokeFunction"],
                                        "Resource": {"Fn::GetAtt": ["TaggerFn", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["TaggerFn", "Arn"]}},
            "BatchRoleArn": {"Value": {"Fn::GetAtt": ["BatchOpsRole", "Arn"]}},
        },
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]
    function_arn = result["outputs"]["FunctionArn"]
    batch_role_arn = result["outputs"]["BatchRoleArn"]
    # Registered after _deploy_cfn's on_cleanup(delete_stack), so LIFO runs this first:
    # CloudFormation cannot delete a non-empty AWS::S3::Bucket, so the bucket this check
    # fills must be emptied before the stack deletion this check already scheduled runs.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))

    keys = ["obj1.txt", "obj2.txt"]
    for key in keys:
        s3.put_object(Bucket=bucket, Key=key, Body=key.encode())

    manifest_body = "".join(f"{bucket},{key}\n" for key in keys).encode()
    manifest_resp = s3.put_object(Bucket=bucket, Key="manifest.csv", Body=manifest_body)
    etag = manifest_resp["ETag"]

    def _create_job():
        try:
            resp = s3control.create_job(
                AccountId=account_id,
                ConfirmationRequired=False,
                Operation={"LambdaInvoke": {"FunctionArn": function_arn}},
                Report={"Enabled": False},
                Manifest={
                    "Spec": {
                        "Format": "S3BatchOperations_CSV_20180820",
                        "Fields": ["Bucket", "Key"],
                    },
                    "Location": {
                        "ObjectArn": f"arn:aws:s3:::{bucket}/manifest.csv",
                        "ETag": etag,
                    },
                },
                Priority=1,
                RoleArn=batch_role_arn,
                ClientRequestToken=_xname(ctx, "job-token"),
            )
            return resp["JobId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDenied":
                return None
            raise

    job_id = _poll_until(
        _create_job,
        lambda j: j is not None,
        timeout_s=90.0,
        interval_s=5.0,
        description="S3 Batch Operations job created (batch role trust propagated)",
    )

    def _job_status():
        return s3control.describe_job(AccountId=account_id, JobId=job_id)["Job"]

    job = _poll_until(
        _job_status,
        lambda j: j["Status"] in {"Complete", "Failed", "Cancelled"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"S3 Batch Operations job {job_id} reaches a terminal state",
    )
    assert job["Status"] == "Complete", (
        f"batch job {job_id} settled into {job['Status']!r} "
        f"(reasons {job.get('FailureReasons')!r}), expected Complete"
    )
    assert job["ProgressSummary"]["NumberOfTasksSucceeded"] == len(keys), (
        f"expected {len(keys)} succeeded tasks, "
        f"progress summary reported {job['ProgressSummary']!r}"
    )
    assert job["ProgressSummary"]["NumberOfTasksFailed"] == 0, (
        f"expected zero failed tasks, progress summary reported {job['ProgressSummary']!r}"
    )

    for key in keys:
        tags = s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
        assert {"Key": "processed", "Value": "true"} in tags, (
            f"object {key!r} carried tags {tags!r} after the batch job completed, "
            "expected the Lambda-applied {'processed': 'true'} tag"
        )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
