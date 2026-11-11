"""deploy-glue-job-via-cloudformation-executes-successfully."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-glue-job-via-cloudformation-executes-successfully"
GROUP = "deploy"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job deployed via AWS::Glue::Job can be started and reaches SUCCEEDED, proving
    the deployed script definition is actually executable -- not merely persisted."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    script_key = "scripts/trivial_job.py"
    script_body = b"print('sim2real behavioral job ran successfully')\n"
    s3.put_object(Bucket=bucket, Key=script_key, Body=script_body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=script_key))
    script_location = f"s3://{bucket}/{script_key}"

    role_arn = _create_glue_role(ctx)

    job_name = ctx.unique_name("sim2real-behav-job-")
    stack_name = ctx.unique_name("sim2real-behav-jobstack-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyJob": {
                    "Type": "AWS::Glue::Job",
                    "Properties": {
                        "Name": job_name,
                        "Role": role_arn,
                        "Command": {
                            "Name": "pythonshell",
                            "PythonVersion": "3.9",
                            "ScriptLocation": script_location,
                        },
                        "MaxCapacity": 0.0625,
                        "GlueVersion": "3.0",
                    },
                }
            },
        }
    )
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, {"CREATE_FAILED", "ROLLBACK_COMPLETE"})

    described = glue.get_job(JobName=job_name)["Job"]
    assert described["Name"] == job_name, f"expected job name {job_name!r}, got {described['Name']!r}"
    assert described["Role"] == role_arn, f"expected role {role_arn!r}, got {described['Role']!r}"
    assert described["Command"]["ScriptLocation"] == script_location, (
        f"expected script location {script_location!r}, got {described['Command']['ScriptLocation']!r}"
    )

    run_id = _start_job_run_with_retry(ctx, job_name)

    final_state = _poll_until(
        lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]["JobRunState"],
        lambda state: state in {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"},
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final_state == "SUCCEEDED", f"deployed job run ended in {final_state}, not SUCCEEDED"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-job-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is S3's region-less default: passing a LocationConstraint for it is itself
    # rejected, so the literal here pins the one region that must be omitted, not one that's hardcoded.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-jobrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    )
    return role_arn


def _start_job_run_with_retry(ctx, job_name, timeout_s=60.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except Exception as exc:  # role/IAM propagation delay
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"could not start job run after retries: {last_exc}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


def _wait_for_stack_status(ctx, stack_name, success_statuses, failure_statuses, timeout_s=180.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            time.sleep(2)
            continue
        last_status = stacks[0]["StackStatus"]
        if last_status in success_statuses:
            return last_status
        if last_status in failure_statuses:
            raise AssertionError(f"stack {stack_name} reached failure status {last_status}")
        time.sleep(3)
    raise AssertionError(f"stack {stack_name} did not reach {success_statuses} in {timeout_s}s (last={last_status})")


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 180.0
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception as exc:
            if "does not exist" in str(exc):
                return
            raise
        stacks = resp.get("Stacks", [])
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} teardown reached DELETE_FAILED")
        time.sleep(3)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within 180s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
