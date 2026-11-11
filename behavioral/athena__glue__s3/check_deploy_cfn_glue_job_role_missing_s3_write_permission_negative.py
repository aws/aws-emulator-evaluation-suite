"""deploy-cfn-glue-job-role-missing-s3-write-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-glue-job-role-missing-s3-write-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["athena", "glue", "s3"]

_JOB_SCRIPT = (
    "import sys\n"
    "import boto3\n"
    "\n"
    "def _arg(name):\n"
    "    return sys.argv[sys.argv.index(name) + 1]\n"
    "\n"
    "bucket = _arg('--BUCKET')\n"
    "out_key = _arg('--OUT_KEY')\n"
    "s3 = boto3.client('s3')\n"
    "data = s3.get_object(Bucket=bucket, Key='src/input.txt')['Body'].read()\n"
    "s3.put_object(Bucket=bucket, Key=out_key, Body=data)\n"
)


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed Glue Job whose role is denied s3:PutObject fails at runtime and writes no
    output object, while a sibling job in the SAME stack with proper write access (positive
    control) succeeds and writes the expected bytes."""
    bucket_name = _xname(ctx, "jobneg-bkt")
    good_role_name = _xname(ctx, "good-job-role")
    bad_role_name = _xname(ctx, "bad-job-role")

    trust_glue = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    template = {
        "Resources": {
            "DataBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name, "Tags": _xsvc_tags_kv()},
            },
            "GoodJobRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": good_role_name,
                    "AssumeRolePolicyDocument": trust_glue,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "s3-read-write",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject"],
                                        "Resource": [
                                            {"Fn::Sub": "${DataBucket.Arn}/scripts/*"},
                                            {"Fn::Sub": "${DataBucket.Arn}/src/*"},
                                        ],
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:PutObject"],
                                        "Resource": [
                                            {"Fn::Sub": "${DataBucket.Arn}/out/good/*"}
                                        ],
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": _xsvc_tags_kv(),
                },
            },
            # Read-only: no s3:PutObject grant anywhere, so the job can fetch the input but
            # is denied when it tries to write the output object.
            "BadJobRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": bad_role_name,
                    "AssumeRolePolicyDocument": trust_glue,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "s3-read-only",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject"],
                                        "Resource": [
                                            {"Fn::Sub": "${DataBucket.Arn}/scripts/*"},
                                            {"Fn::Sub": "${DataBucket.Arn}/src/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": _xsvc_tags_kv(),
                },
            },
        },
    }

    deploy = _deploy_cfn(ctx, json.dumps(template))
    del deploy  # outputs unused — role ARNs are derived deterministically below

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket_name, Key="scripts/job.py", Body=_JOB_SCRIPT.encode())
    s3.put_object(Bucket=bucket_name, Key="src/input.txt", Body=b"hello-glue-job\n")
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    good_role_arn = f"arn:aws:iam::{account_id}:role/{good_role_name}"
    bad_role_arn = f"arn:aws:iam::{account_id}:role/{bad_role_name}"

    glue = ctx.client("glue")
    good_job_name = _xname(ctx, "good-job")
    bad_job_name = _xname(ctx, "bad-job")
    command = {
        "Name": "pythonshell",
        "PythonVersion": "3.9",
        "ScriptLocation": f"s3://{bucket_name}/scripts/job.py",
    }
    glue.create_job(
        Name=good_job_name, Role=good_role_arn, Command=command, MaxCapacity=0.0625,
        Tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=good_job_name))
    glue.create_job(
        Name=bad_job_name, Role=bad_role_arn, Command=command, MaxCapacity=0.0625,
        Tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=bad_job_name))

    good_run_id = glue.start_job_run(
        JobName=good_job_name,
        Arguments={"--BUCKET": bucket_name, "--OUT_KEY": "out/good/output.txt"},
    )["JobRunId"]
    bad_run_id = glue.start_job_run(
        JobName=bad_job_name,
        Arguments={"--BUCKET": bucket_name, "--OUT_KEY": "out/bad/output.txt"},
    )["JobRunId"]

    terminal_states = {"SUCCEEDED", "FAILED", "ERROR", "TIMEOUT", "STOPPED"}
    good_run = _poll_until(
        lambda: glue.get_job_run(JobName=good_job_name, RunId=good_run_id)["JobRun"],
        lambda r: r["JobRunState"] in terminal_states,
        timeout_s=600,
        interval_s=10.0,
        description=f"job run {good_run_id} terminal",
    )
    bad_run = _poll_until(
        lambda: glue.get_job_run(JobName=bad_job_name, RunId=bad_run_id)["JobRun"],
        lambda r: r["JobRunState"] in terminal_states,
        timeout_s=600,
        interval_s=10.0,
        description=f"job run {bad_run_id} terminal",
    )

    # Positive control: the properly-permissioned job in the SAME stack succeeds and writes.
    assert good_run["JobRunState"] == "SUCCEEDED", good_run.get("ErrorMessage")
    good_obj = s3.get_object(Bucket=bucket_name, Key="out/good/output.txt")
    assert good_obj["Body"].read() == b"hello-glue-job\n"

    # Negative: the job whose role lacks s3:PutObject fails at runtime and writes nothing.
    assert bad_run["JobRunState"] == "FAILED", bad_run.get("ErrorMessage")
    bad_message = bad_run.get("ErrorMessage") or ""
    # The job script's own S3 refusal surfaces verbatim, signed by Glue's runner session.
    expected_message = (
        "ClientError: An error occurred (AccessDenied) when calling the PutObject operation: "
        f"User: arn:aws:sts::{account_id}:assumed-role/{bad_role_name}/GlueJobRunnerSession "
        "is not authorized to perform: s3:PutObject on resource: "
        f'"arn:aws:s3:::{bucket_name}/out/bad/output.txt" '
        "because no identity-based policy allows the s3:PutObject action"
    )
    assert bad_message == expected_message, (
        f"bad job run failed for the wrong reason; ErrorMessage was {bad_message!r}"
    )
    head_code, head_message = _error_code(
        lambda: s3.head_object(Bucket=bucket_name, Key="out/bad/output.txt")
    )
    assert head_code == "404", head_code
    assert head_message == "Not Found", head_message


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error_code(fn) -> tuple[str, str]:
    """fn()'s error code and message; a call that succeeds where a refusal is expected fails."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    token = None
    while True:
        kwargs: dict[str, Any] = {"Bucket": bucket_name}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        objs = resp.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        if not resp.get("IsTruncated"):
            break
        token = resp.get("NextContinuationToken")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
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
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
