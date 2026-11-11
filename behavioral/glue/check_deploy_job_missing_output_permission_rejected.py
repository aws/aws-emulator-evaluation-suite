"""deploy-job-missing-output-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-job-missing-output-permission-rejected"
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


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two CloudFormation-deployed Glue jobs differing only in an s3:PutObject grant, the one
    lacking it fails with AccessDenied and writes nothing; the other, and the first once granted,
    succeed and write their output, so Glue job runs enforce the role's IAM permissions."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    script = (
        "import sys\n"
        "import boto3\n"
        "\n"
        "def _get_arg(name):\n"
        "    key = '--' + name\n"
        "    for i, a in enumerate(sys.argv):\n"
        "        if a == key:\n"
        "            return sys.argv[i + 1]\n"
        "    raise SystemExit('missing arg ' + key)\n"
        "\n"
        "bucket = _get_arg('bucket')\n"
        "output_key = _get_arg('output_key')\n"
        "s3 = boto3.client('s3')\n"
        "s3.put_object(Bucket=bucket, Key=output_key, Body=b'ok')\n"
        "print('done')\n"
    )
    _put_object(ctx, bucket, "scripts/write_output.py", script)
    script_location = f"s3://{bucket}/scripts/write_output.py"
    bucket_arn = f"arn:aws:s3:::{bucket}"

    good_role_arn, _good_role_name = _create_glue_role(
        ctx,
        "good",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"{bucket_arn}/scripts/write_output.py"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"{bucket_arn}/results/*"],
            },
        ],
    )
    bad_role_arn, bad_role_name = _create_glue_role(
        ctx,
        "bad",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"{bucket_arn}/scripts/write_output.py"],
            }
            # deliberately NO s3:PutObject grant -- the one thing broken
        ],
    )
    job_good = ctx.unique_name("sim2real-glue-jobgood-")
    job_bad = ctx.unique_name("sim2real-glue-jobbad-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "JobNameGood": {"Type": "String"},
            "JobNameBad": {"Type": "String"},
            "GoodRoleArn": {"Type": "String"},
            "BadRoleArn": {"Type": "String"},
            "ScriptLocation": {"Type": "String"},
        },
        "Resources": {
            "GlueJobGood": {
                "Type": "AWS::Glue::Job",
                "Properties": {
                    "Name": {"Ref": "JobNameGood"},
                    "Role": {"Ref": "GoodRoleArn"},
                    "Command": {
                        "Name": "pythonshell",
                        "ScriptLocation": {"Ref": "ScriptLocation"},
                        "PythonVersion": "3.9",
                    },
                    "MaxCapacity": 0.0625,
                    "GlueVersion": "3.0",
                },
            },
            "GlueJobBad": {
                "Type": "AWS::Glue::Job",
                "Properties": {
                    "Name": {"Ref": "JobNameBad"},
                    "Role": {"Ref": "BadRoleArn"},
                    "Command": {
                        "Name": "pythonshell",
                        "ScriptLocation": {"Ref": "ScriptLocation"},
                        "PythonVersion": "3.9",
                    },
                    "MaxCapacity": 0.0625,
                    "GlueVersion": "3.0",
                },
            },
        },
    }
    _deploy_stack(
        ctx,
        template,
        {
            "JobNameGood": job_good,
            "JobNameBad": job_bad,
            "GoodRoleArn": good_role_arn,
            "BadRoleArn": bad_role_arn,
            "ScriptLocation": script_location,
        },
    )

    good_key = "results/good.txt"
    bad_key = "results/bad.txt"

    # IAM grants propagate eventually, so the good job's run is retried; the bad job's failure is
    # permanent by construction and gets one attempt.
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    good_run = _run_job_run_with_retry(
        glue, job_good, {"--bucket": bucket, "--output_key": good_key}
    )
    bad_run_id = glue.start_job_run(
        JobName=job_bad, Arguments={"--bucket": bucket, "--output_key": bad_key}
    )["JobRunId"]
    bad_run = _wait_job_run_terminal(glue, job_bad, bad_run_id)

    # Positive control: the job whose role has the permission succeeds and its
    # output object is actually written.
    assert good_run["JobRunState"] == "SUCCEEDED", good_run.get("ErrorMessage")
    body = s3.get_object(Bucket=bucket, Key=good_key)["Body"].read()
    assert body == b"ok", body

    # Negative: the job whose role lacks exactly the PutObject permission fails,
    # and (crucially) the effect is absent -- no output object was written.
    assert bad_run["JobRunState"] == "FAILED", bad_run
    assert bad_run.get("ErrorMessage") == (
        "ClientError: An error occurred (AccessDenied) when calling the PutObject operation: "
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{bad_role_name}/GlueJobRunnerSession "
        f'is not authorized to perform: s3:PutObject on resource: "arn:aws:s3:::{bucket}/{bad_key}" '
        "because no identity-based policy allows the s3:PutObject action"
    ), bad_run
    code = _error_code(lambda: s3.get_object(Bucket=bucket, Key=bad_key))
    assert code == ("NoSuchKey", "The specified key does not exist."), code

    # Restore: granting the missing statement makes the same job succeed.
    iam = ctx.client("iam")
    restore_policy_name = f"{bad_role_name}-restore"
    iam.put_role_policy(
        RoleName=bad_role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject"],
                        "Resource": [f"{bucket_arn}/results/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName=restore_policy_name)
    )

    restored_key = "results/bad-restored.txt"
    restored_run = _run_job_run_with_retry(
        glue, job_bad, {"--bucket": bucket, "--output_key": restored_key}
    )
    assert restored_run["JobRunState"] == "SUCCEEDED", restored_run.get("ErrorMessage")
    restored_body = s3.get_object(Bucket=bucket, Key=restored_key)["Body"].read()
    assert restored_body == b"ok", restored_body


def _error_code(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    bucket = ctx.unique_name("sim2real-glue-negjob-").lower()
    # S3 rejects an explicit LocationConstraint for us-east-1.
    if ctx.region == "us-east-1":
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


def _create_glue_role(ctx, tag: str, statements) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-glue-{tag}role-")
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
    return role_arn, role_name


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


def _wait_job_run_terminal(glue, job_name: str, run_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    def probe():
        return glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]

    def done(job_run):
        return job_run["JobRunState"] in _JOB_RUN_TERMINAL

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


def _start_job_run_with_retry(glue, job_name: str, arguments: dict, timeout_s: float = 90.0, interval_s: float = 10.0):
    # Glue's concurrency bookkeeping lags GetJobRun reporting the prior run terminal, so a
    # same-job restart can briefly see ConcurrentRunsExceededException; retry only that code.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return glue.start_job_run(JobName=job_name, Arguments=arguments)["JobRunId"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConcurrentRunsExceededException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _run_job_run_with_retry(glue, job_name: str, arguments: dict, timeout_s: float = 120.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        run_id = _start_job_run_with_retry(glue, job_name, arguments)
        last = _wait_job_run_terminal(glue, job_name, run_id)
        if last["JobRunState"] == "SUCCEEDED" or time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
