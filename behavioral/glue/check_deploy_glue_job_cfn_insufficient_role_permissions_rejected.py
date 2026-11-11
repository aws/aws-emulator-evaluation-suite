"""deploy-glue-job-cfn-insufficient-role-permissions-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-glue-job-cfn-insufficient-role-permissions-rejected"
GROUP = "deploy"
SERVICES = ["glue"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  GoodJobName:
    Type: String
  GoodRoleArn:
    Type: String
  GoodScriptLocation:
    Type: String
  BadJobName:
    Type: String
  BadRoleArn:
    Type: String
  BadScriptLocation:
    Type: String
Resources:
  GoodJob:
    Type: AWS::Glue::Job
    Properties:
      Name: !Ref GoodJobName
      Role: !Ref GoodRoleArn
      GlueVersion: "3.0"
      MaxCapacity: 0.0625
      Command:
        Name: pythonshell
        PythonVersion: "3.9"
        ScriptLocation: !Ref GoodScriptLocation
  BadJob:
    Type: AWS::Glue::Job
    Properties:
      Name: !Ref BadJobName
      Role: !Ref BadRoleArn
      GlueVersion: "3.0"
      MaxCapacity: 0.0625
      Command:
        Name: pythonshell
        PythonVersion: "3.9"
        ScriptLocation: !Ref BadScriptLocation
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A Glue job whose role cannot read its S3 script fails its run and writes no marker,
    while an identical, properly-permissioned job in the same stack succeeds (positive control)."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-glue-perm-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    good_marker = "output/good-marker.txt"
    bad_marker = "output/bad-marker.txt"
    good_script_key = "scripts/good.py"
    bad_script_key = "scripts/bad.py"
    s3.put_object(Bucket=bucket, Key=good_script_key,
                  Body=_script_body(bucket, good_marker))
    s3.put_object(Bucket=bucket, Key=bad_script_key,
                  Body=_script_body(bucket, bad_marker))

    good_role_arn = _create_role_with_s3_access(ctx, iam, bucket)
    bad_role_arn = _create_role_without_s3_access(ctx, iam)

    good_job_name = ctx.unique_name("sim2real-glue-goodjob-")
    bad_job_name = ctx.unique_name("sim2real-glue-badjob-")
    stack_name = ctx.unique_name("sim2real-glue-permstack-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 440})

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "GoodJobName", "ParameterValue": good_job_name},
            {"ParameterKey": "GoodRoleArn", "ParameterValue": good_role_arn},
            {"ParameterKey": "GoodScriptLocation", "ParameterValue": f"s3://{bucket}/{good_script_key}"},
            {"ParameterKey": "BadJobName", "ParameterValue": bad_job_name},
            {"ParameterKey": "BadRoleArn", "ParameterValue": bad_role_arn},
            {"ParameterKey": "BadScriptLocation", "ParameterValue": f"s3://{bucket}/{bad_script_key}"},
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup_stack)

    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    good_run_id = _start_job_run_with_retry(glue, good_job_name)
    bad_run_id = _start_job_run_with_retry(glue, bad_job_name)

    good_run = _poll_until(
        lambda: glue.get_job_run(JobName=good_job_name, RunId=good_run_id)["JobRun"],
        lambda r: r["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"),
        timeout_s=420, interval_s=10,
    )
    bad_run = _poll_until(
        lambda: glue.get_job_run(JobName=bad_job_name, RunId=bad_run_id)["JobRun"],
        lambda r: r["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"),
        timeout_s=420, interval_s=10,
    )

    # Positive control: the properly-permissioned job succeeds and its side effect exists.
    assert good_run["JobRunState"] == "SUCCEEDED", good_run.get("ErrorMessage")
    _assert_object_exists(s3, bucket, good_marker)

    # Negative: the under-permissioned job does NOT succeed, and its side effect never happened.
    assert bad_run["JobRunState"] == "FAILED", bad_run
    _assert_object_absent(s3, bucket, bad_marker)


# ===== helpers =====

def _script_body(bucket: str, marker_key: str) -> bytes:
    return (
        "import boto3\n"
        f"boto3.client('s3').put_object(Bucket='{bucket}', Key='{marker_key}', Body=b'done')\n"
        "print('marker written')\n"
    ).encode("utf-8")


def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit
        # LocationConstraint; this is an S3 API quirk, not a hardcoded target region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_role_with_s3_access(ctx: Any, iam: Any, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-glue-goodrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    inline_policy_name = "sim2real-s3-rw"
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    return role_arn


def _create_role_without_s3_access(ctx: Any, iam: Any) -> str:
    """A role Glue can assume, but with zero attached/inline permissions -- it
    cannot even fetch its own job script from S3."""
    role_name = ctx.unique_name("sim2real-glue-badrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _start_job_run_with_retry(glue: Any, job_name: str) -> str:
    """Bounded retry, not a fixed sleep: IAM role/trust-policy propagation to Glue's
    control plane is eventually consistent (up to ~90s in practice), and a fresh role
    can trip AccessDeniedException on StartJobRun before it has fully propagated. This
    is unrelated to the S3-permission gap the check is testing -- that shows up later,
    as a FAILED job run, not as a StartJobRun error."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _assert_object_exists(s3: Any, bucket: str, key: str) -> None:
    from botocore.exceptions import ClientError

    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        raise AssertionError(f"expected marker object {key!r} to exist: {exc}") from exc


def _assert_object_absent(s3: Any, bucket: str, key: str) -> None:
    from botocore.exceptions import ClientError

    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "404", f"unexpected error checking absent marker: {code}"
        return
    raise AssertionError(f"marker object {key!r} unexpectedly exists (job ran despite no permissions)")


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
