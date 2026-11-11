"""glue-job-failed-event-missing-target-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-job-failed-event-missing-target-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["athena", "glue", "s3"]

GLUE_SERVICE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule matching a Glue Job FAILED event delivers it only to the SQS target whose queue policy
    lets events.amazonaws.com SendMessage; the queue without that policy receives nothing, since
    EventBridge drops the delivery silently instead of failing PutTargets."""
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_role(ctx, bucket)
    job_name = _create_pythonshell_job(
        ctx, role_arn, bucket, "import sys\nsys.exit(1)\n", "fail-job"
    )

    denied_url, denied_arn = _create_queue(ctx)  # no resource policy -> default deny
    allowed_url, allowed_arn = _create_queue(ctx)

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-fail-rule-")
    pattern = {
        "source": ["aws.glue"],
        "detail-type": ["Glue Job State Change"],
        "detail": {"jobName": [job_name], "state": ["FAILED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])
    _set_queue_policy(ctx, allowed_url, allowed_arn, rule_arn)  # only the "allowed" queue gets a policy
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "denied", "Arn": denied_arn},
            {"Id": "allowed", "Arn": allowed_arn},
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["denied", "allowed"]))

    run_id, state = _run_job_to_terminal_state(ctx, job_name)
    assert state == "FAILED", f"expected job to FAIL, got {state}"

    message = _wait_for_matching_message(ctx, allowed_url, job_name, timeout_s=180)
    assert message["detail"]["jobName"] == job_name
    assert message["detail"]["state"] == "FAILED"

    # The allowed queue's delivery proves the rule fired; 45 s more covers a late denied delivery.
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + 45.0
    received: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=denied_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        received.extend(resp.get("Messages", []))
        if received:
            break
    assert received == [], f"expected no delivery to the unpermitted queue, got {received!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-glue-evt-")
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket_name


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [
                {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _create_glue_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=GLUE_SERVICE_ROLE_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=GLUE_SERVICE_ROLE_POLICY_ARN))
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(s3_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return role_arn


def _create_pythonshell_job(ctx, role_arn: str, bucket_name: str, script_body: str, name_prefix: str) -> str:
    s3 = ctx.client("s3")
    script_key = f"scripts/{ctx.unique_name('script-')}.py"
    s3.put_object(Bucket=bucket_name, Key=script_key, Body=script_body.encode())
    glue = ctx.client("glue")
    job_name = ctx.unique_name(f"sim2real-{name_prefix}-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "pythonshell",
            "ScriptLocation": f"s3://{bucket_name}/{script_key}",
            "PythonVersion": "3.9",
        },
        MaxCapacity=0.0625,
        Timeout=5,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run(ctx, job_name: str, timeout_s: float = 60.0) -> str:
    """Retry StartJobRun every 2 s to a deadline while its fresh role propagates."""
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_for_terminal_job_state(ctx, job_name: str, run_id: str, timeout_s: float = 300.0) -> str:
    glue = ctx.client("glue")
    terminal = {"SUCCEEDED", "FAILED", "TIMEOUT", "STOPPED", "ERROR"}
    return _poll_until(
        lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]["JobRunState"],
        lambda s: s in terminal,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"glue job {job_name} run {run_id} reaching a terminal state",
    )


def _run_job_to_terminal_state(
    ctx, job_name: str, timeout_s: float = 300.0, role_propagation_deadline_s: float = 180.0
) -> tuple[str, str]:
    """Run the job to a terminal state, rerunning while it fails with "assume role permissions",
    which is IAM propagation lag rather than the script's own sys.exit(1)."""
    glue = ctx.client("glue")
    retry_deadline = time.monotonic() + role_propagation_deadline_s
    while True:
        run_id = _start_job_run(ctx, job_name)
        state = _wait_for_terminal_job_state(ctx, job_name, run_id, timeout_s=timeout_s)
        if state in ("FAILED", "ERROR") and time.monotonic() < retry_deadline:
            err = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"].get("ErrorMessage") or ""
            if "assume role permissions" in err:
                time.sleep(2)
                continue
        return run_id, state


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-glue-evt-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _set_queue_policy(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _wait_for_matching_message(ctx, queue_url: str, job_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("detail", {}).get("jobName") == job_name:
                return body
    raise AssertionError(f"no matching Glue Job State Change event for job {job_name} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
