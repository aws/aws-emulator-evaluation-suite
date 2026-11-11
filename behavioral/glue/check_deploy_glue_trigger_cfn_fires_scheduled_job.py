"""deploy-glue-trigger-cfn-fires-scheduled-job."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "deploy-glue-trigger-cfn-fires-scheduled-job"
GROUP = "deploy"
SERVICES = ["glue"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  TriggerName:
    Type: String
  JobName:
    Type: String
Resources:
  GlueTrigger:
    Type: AWS::Glue::Trigger
    Properties:
      Name: !Ref TriggerName
      Type: SCHEDULED
      Schedule: "cron(0/5 * * * ? *)"
      StartOnCreation: true
      Actions:
        - JobName: !Ref JobName
Outputs:
  TriggerNameOut:
    Value: !Ref TriggerName
"""

_SCRIPT_BODY = b"print('sim2real glue behavioral scheduled-trigger job ran')\n"


# timing:real-time — schedule: 272 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "timing:real-time")
def run(ctx: Any) -> None:
    """A SCHEDULED trigger deployed via AWS::Glue::Trigger with StartOnCreation
    actually starts its target job run once its cron schedule elapses -- not just
    a metadata object that sits ACTIVATED and never fires anything."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-glue-trig-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    script_key = "scripts/hello.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=_SCRIPT_BODY)
    script_location = f"s3://{bucket}/{script_key}"

    role_arn = _create_job_role(ctx, iam, bucket)

    job_name = ctx.unique_name("sim2real-glue-trigjob-")
    _create_job_with_retry(glue, job_name, role_arn, script_location)
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    trigger_name = ctx.unique_name("sim2real-glue-trigger-")
    stack_name = ctx.unique_name("sim2real-glue-trigstack-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 440})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "TriggerName", "ParameterValue": trigger_name},
            {"ParameterKey": "JobName", "ParameterValue": job_name},
        ],
    )
    ctx.on_cleanup(_cleanup_stack)

    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    trigger = glue.get_trigger(Name=trigger_name)["Trigger"]
    assert trigger["Type"] == "SCHEDULED", f"expected SCHEDULED, got {trigger['Type']!r}"
    trigger = _poll_until(
        lambda: glue.get_trigger(Name=trigger_name)["Trigger"],
        lambda t: t["State"] == "ACTIVATED",
        timeout_s=60, interval_s=5,
    )

    # Wait for the schedule to elapse and the trigger to actually start a run of
    # its target job -- this is the behavior a metadata-only stub cannot produce.
    def _matching_runs() -> list:
        runs = glue.get_job_runs(JobName=job_name)["JobRuns"]
        return [r for r in runs if r.get("TriggerName") == trigger_name]

    matched = _poll_until(_matching_runs, lambda runs: len(runs) >= 1, timeout_s=600, interval_s=15)
    fired_run = matched[0]
    assert fired_run["TriggerName"] == trigger_name, (
        f"expected a run tagged with trigger {trigger_name!r}, got {fired_run.get('TriggerName')!r}"
    )

    # And that fired run itself progresses to a terminal state.
    run_id = fired_run["Id"]

    def _run_probe() -> dict:
        return glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]

    terminal_run = _poll_until(
        _run_probe,
        lambda r: r["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"),
        timeout_s=300, interval_s=10,
    )
    assert terminal_run["JobRunState"] == "SUCCEEDED", terminal_run.get("ErrorMessage")


# ===== helpers =====

def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_job_role(ctx: Any, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-glue-trigrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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


def _create_job_with_retry(glue: Any, job_name: str, role_arn: str, script_location: str) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    while True:
        try:
            glue.create_job(
                Name=job_name,
                Role=role_arn,
                GlueVersion="3.0",
                MaxCapacity=0.0625,
                Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script_location},
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidInputException" and time.monotonic() < deadline:
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
