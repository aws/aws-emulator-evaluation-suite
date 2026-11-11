"""cfn-deploy-glue-job-role-missing-s3-access-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-glue-job-role-missing-s3-access-negative"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job whose role has only AWSGlueServiceRole fails because it cannot read its own script from
    the bucket ("Script file doesn't exist", 404), while a same-stack job whose role can read the bucket
    succeeds and writes its output."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    job_full = _xname(ctx, "job-full")
    job_limited = _xname(ctx, "job-limited")
    role_full = _xname(ctx, "role-full")
    role_limited = _xname(ctx, "role-limited")

    def _job_props(name: str, role_logical: str) -> dict[str, Any]:
        return {
            "Name": name,
            "Role": {"Fn::GetAtt": [role_logical, "Arn"]},
            "GlueVersion": "3.0",
            "Timeout": 10,
            "Command": {
                "Name": "pythonshell",
                "PythonVersion": "3.9",
                "ScriptLocation": {"Fn::Sub": "s3://${Bucket}/scripts/etl.py"},
            },
            "MaxCapacity": 0.0625,
        }

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
            "FullRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_full,
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
            "LimitedRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_limited,
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
                    # deliberately NO policy granting access to this bucket
                },
            },
            "JobFull": {
                "Type": "AWS::Glue::Job",
                "DependsOn": ["FullRole", "Bucket"],
                "Properties": _job_props(job_full, "FullRole"),
            },
            "JobLimited": {
                "Type": "AWS::Glue::Job",
                "DependsOn": ["LimitedRole", "Bucket"],
                "Properties": _job_props(job_limited, "LimitedRole"),
            },
        },
        "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]

    s3.put_object(Bucket=bucket, Key="scripts/etl.py", Body=_SCRIPT.encode())
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    full_result = _run_job_to_terminal(
        ctx,
        glue,
        job_full,
        {"--JOB_NAME": job_full, "--OUTPUT_BUCKET": bucket, "--OUTPUT_KEY": "output/full.txt"},
    )
    limited_result = _run_job_to_terminal(
        ctx,
        glue,
        job_limited,
        {"--JOB_NAME": job_limited, "--OUTPUT_BUCKET": bucket, "--OUTPUT_KEY": "output/limited.txt"},
    )

    # Positive control: the role WITH S3 access succeeds and really writes the object.
    assert full_result["JobRunState"] == "SUCCEEDED", (
        f"full-role job run ended {full_result['JobRunState']!r}, expected SUCCEEDED: "
        f"{full_result.get('ErrorMessage')!r}"
    )
    obj = s3.get_object(Bucket=bucket, Key="output/full.txt")
    body = obj["Body"].read()
    assert body == b"etl-complete", f"full-role job wrote {body!r}, expected b'etl-complete'"

    # Negative: the role WITHOUT S3 access to this bucket fails, and the effect is absent.
    # Real AWS masks the underlying denial as a not-found on the script fetch itself, rather
    # than surfacing AccessDenied -- the job never gets far
    # enough to attempt the output write.
    assert limited_result["JobRunState"] == "FAILED", (
        f"limited-role job run ended {limited_result['JobRunState']!r}, expected FAILED: "
        f"{limited_result.get('ErrorMessage')!r}"
    )
    limited_message = limited_result.get("ErrorMessage") or ""
    assert "Script file doesn't exist" in limited_message and "etl.py" in limited_message, (
        f"limited-role job failed for the wrong reason; ErrorMessage was "
        f"{limited_message!r}, expected Glue's script-access error naming etl.py (the "
        f"AWSGlueServiceRole managed policy alone cannot read an arbitrary bucket's script)"
    )
    limited_code = _error_code(lambda: s3.head_object(Bucket=bucket, Key="output/limited.txt"))
    assert limited_code == "404", (
        f"head_object on the limited-role output returned {limited_code!r}, expected 404 "
        f"(no object) — the denied job may have written its output anyway"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error_code(fn):
    """The ClientError code `fn` raises; an unexpected success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("the call succeeded where an error was expected")


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


_IAM_PROPAGATION_MARKER = "should be given assume role permissions"


def _run_job_to_terminal(ctx, glue, job_name: str, arguments: dict, *, timeout_s: float = 420.0) -> dict:
    """Start the job and poll to a terminal state, retrying with a fresh run only when the
    failure is the IAM trust-policy propagation race (Glue reports this as a FAILED run, not
    a StartJobRun error, seconds after a same-run CFN role becomes assumable) — never when the
    failure is the S3-access denial under test."""
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        run_id = _start_job_with_retry(ctx, job_name, arguments)
        last = _poll_until(
            lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
            lambda r: r["JobRunState"] in _TERMINAL_JOB_STATES,
            timeout_s=max(30.0, deadline - time.monotonic()),
            interval_s=10.0,
            description=f"job run {run_id} ({job_name}) to finish",
        )
        if last["JobRunState"] == "FAILED" and _IAM_PROPAGATION_MARKER in (last.get("ErrorMessage") or ""):
            time.sleep(2)
            continue
        return last
    raise AssertionError(f"job {job_name} kept hitting IAM propagation within {timeout_s}s: {last!r}")


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
