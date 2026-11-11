"""cfn-deploy-glue-job-s3-script-location-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-glue-job-s3-script-location-positive"
GROUP = "arn-resolution"
SERVICES = ["emr", "glue", "s3"]

_TERMINAL_JOB_STATES = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}

_SCRIPT = (
    "import sys\n"
    "import boto3\n"
    "from awsglue.utils import getResolvedOptions\n"
    "args = getResolvedOptions(sys.argv, ['JOB_NAME', 'OUTPUT_BUCKET', 'OUTPUT_KEY'])\n"
    "s3 = boto3.client('s3')\n"
    "s3.put_object(Bucket=args['OUTPUT_BUCKET'], Key=args['OUTPUT_KEY'], Body=b'etl-complete')\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job resource whose Command.ScriptLocation is an S3 URI created in the same stack
    actually resolves and executes that script when run, producing the script's real output."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    job_name = _xname(ctx, "job")
    role_name = _xname(ctx, "role")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
            "JobRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "glue.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "s3access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:PutObject"],
                                        "Resource": {"Fn::Sub": "arn:aws:s3:::${Bucket}/*"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "GlueJob": {
                "Type": "AWS::Glue::Job",
                "DependsOn": ["JobRole", "Bucket"],
                "Properties": {
                    "Name": job_name,
                    "Role": {"Fn::GetAtt": ["JobRole", "Arn"]},
                    "GlueVersion": "3.0",
                    "Timeout": 10,
                    "Command": {
                        "Name": "pythonshell",
                        "PythonVersion": "3.9",
                        "ScriptLocation": {"Fn::Sub": "s3://${Bucket}/scripts/etl.py"},
                    },
                    "MaxCapacity": 0.0625,
                },
            },
        },
        "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]

    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT.encode())
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    run_id = _start_job_with_retry(
        ctx,
        job_name,
        {"--JOB_NAME": job_name, "--OUTPUT_BUCKET": bucket, "--OUTPUT_KEY": "output/marker.txt"},
    )

    job_run = _poll_until(
        lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
        lambda r: r["JobRunState"] in _TERMINAL_JOB_STATES,
        timeout_s=420,
        interval_s=10.0,
        description=f"job run {run_id} to finish",
    )
    assert job_run["JobRunState"] == "SUCCEEDED", (
        f"expected job run {run_id} to end SUCCEEDED, got {job_run['JobRunState']}: "
        f"{job_run.get('ErrorMessage')} log={_job_error_log(ctx, run_id)!r}"
    )

    obj = s3.get_object(Bucket=bucket, Key="output/marker.txt")
    body = obj["Body"].read()
    assert body == b"etl-complete", f"expected b'etl-complete' at {bucket}/output/marker.txt, got {body!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _start_job_with_retry(ctx, job_name: str, arguments: dict, *, attempts: int = 5, backoff_s: float = 15.0) -> str:
    """Bounded retry for IAM role/policy propagation, which is eventually consistent (seconds,
    per IAM docs) — a start_job_run right after CFN CREATE_COMPLETE can hit a role that isn't
    assumable yet."""
    glue = ctx.client("glue")
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(backoff_s)
    assert last_exc is not None
    raise last_exc


def _job_error_log(ctx, run_id: str) -> str:
    logs = ctx.client("logs")
    for group in ("/aws-glue/python-jobs/error", "/aws-glue/python-jobs/output"):
        try:
            events = logs.get_log_events(logGroupName=group, logStreamName=run_id, limit=50)["events"]
        except ClientError:
            continue
        if events:
            return "\n".join(e["message"] for e in events)
    return "<no log events found>"


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
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
    template_body = template.read_text() if hasattr(template, "read_text") else template
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
