"""deploy-glue-job-cfn-executes-successfully."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "deploy-glue-job-cfn-executes-successfully"
GROUP = "deploy"
SERVICES = ["glue"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  JobName:
    Type: String
  RoleArn:
    Type: String
  ScriptLocation:
    Type: String
Resources:
  GlueJob:
    Type: AWS::Glue::Job
    Properties:
      Name: !Ref JobName
      Role: !Ref RoleArn
      GlueVersion: "3.0"
      MaxCapacity: 0.0625
      Command:
        Name: pythonshell
        PythonVersion: "3.9"
        ScriptLocation: !Ref ScriptLocation
Outputs:
  JobNameOut:
    Value: !Ref JobName
"""

_SCRIPT_BODY = b"print('sim2real glue behavioral job ran successfully')\n"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A job deployed via AWS::Glue::Job executes end-to-end when started and
    actually reaches SUCCEEDED -- proving the emulator can run the job's native
    Python-shell command, not just accept StartJobRun and rubber-stamp a state."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-glue-job-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    script_key = "scripts/hello.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT_BODY)
    script_location = f"s3://{bucket}/{script_key}"

    role_arn = _create_job_role(ctx, iam, bucket)

    job_name = ctx.unique_name("sim2real-glue-job-")
    stack_name = ctx.unique_name("sim2real-glue-jobstack-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 440})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "JobName", "ParameterValue": job_name},
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "ScriptLocation", "ParameterValue": script_location},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup_stack)

    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    job = glue.get_job(JobName=job_name)["Job"]
    assert job["Command"]["Name"] == "pythonshell", job["Command"].get("Name")
    assert job["Command"]["ScriptLocation"] == script_location, job["Command"].get("ScriptLocation")
    assert job["Role"] == role_arn, job.get("Role")

    run_id = _start_job_run_with_retry(glue, job_name)

    def _probe() -> dict:
        return glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]

    job_run = _poll_until(
        _probe,
        lambda r: r["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"),
        timeout_s=420, interval_s=10,
    )
    assert job_run["JobRunState"] == "SUCCEEDED", job_run.get("ErrorMessage")


# ===== helpers =====

def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_job_role(ctx: Any, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-glue-job-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    inline_policy_name = "sim2real-s3-read"
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    return role_arn


def _start_job_run_with_retry(glue: Any, job_name: str) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    while True:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool],
                 timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
