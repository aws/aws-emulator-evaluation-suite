"""deploy-job-via-cloudformation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-job-via-cloudformation"
GROUP = "deploy"
SERVICES = ["glue"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
}
_JOB_RUN_TERMINAL = {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Glue::Job can actually be started and reaches a
    terminal SUCCEEDED run state, proving the deployed job definition (Command,
    ScriptLocation, Role) is executable and not merely CREATE_COMPLETE on the stack."""
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx)
    _put_object(ctx, bucket, "scripts/job.py", "print('sim2real glue job ran')\n")
    script_location = f"s3://{bucket}/scripts/job.py"
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_arn = _create_glue_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"{bucket_arn}/scripts/job.py"],
            }
        ],
    )

    job_name = ctx.unique_name("sim2real-glue-job-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "JobName": {"Type": "String"},
            "JobRoleArn": {"Type": "String"},
            "ScriptLocation": {"Type": "String"},
        },
        "Resources": {
            "GlueJob": {
                "Type": "AWS::Glue::Job",
                "Properties": {
                    "Name": {"Ref": "JobName"},
                    "Role": {"Ref": "JobRoleArn"},
                    "Command": {
                        "Name": "pythonshell",
                        "ScriptLocation": {"Ref": "ScriptLocation"},
                        "PythonVersion": "3.9",
                    },
                    "MaxCapacity": 0.0625,
                    "GlueVersion": "3.0",
                },
            }
        },
    }
    _deploy_stack(
        ctx,
        template,
        {"JobName": job_name, "JobRoleArn": role_arn, "ScriptLocation": script_location},
    )

    job = glue.get_job(JobName=job_name)["Job"]
    assert job["Command"]["ScriptLocation"] == script_location, (
        f"expected ScriptLocation {script_location!r}, got "
        f"{job['Command'].get('ScriptLocation')!r}"
    )
    assert job["Role"] == role_arn, f"expected Role {role_arn!r}, got {job.get('Role')!r}"

    run_id = _start_job_run_with_retry(glue, job_name)
    job_run = _wait_job_run_terminal(glue, job_name, run_id)
    assert job_run["JobRunState"] == "SUCCEEDED", job_run.get("ErrorMessage")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-job-").lower()
    if ctx.region == "us-east-1":
        # S3 rejects CreateBucketConfiguration.LocationConstraint for us-east-1 itself.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_object(ctx, bucket: str, key: str, body: str) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))


def _create_glue_role(ctx, statements) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-jrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    managed_policy = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    inline_policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _stack_status(cfn, stack_name: str) -> str:
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
        return resp["Stacks"][0]["StackStatus"]
    except ClientError as e:
        if "does not exist" in str(e):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s == "DELETE_COMPLETE",
        timeout_s=400.0,
        interval_s=10.0,
    )


def _deploy_stack(ctx, template: dict, params: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-glue-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in _STACK_TERMINAL,
        timeout_s=400.0,
        interval_s=10.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE (status={status})")
    return stack_name


def _start_job_run_with_retry(glue, job_name: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_job_run_terminal(glue, job_name: str, run_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    def probe():
        return glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]

    def done(job_run):
        return job_run["JobRunState"] in _JOB_RUN_TERMINAL

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
