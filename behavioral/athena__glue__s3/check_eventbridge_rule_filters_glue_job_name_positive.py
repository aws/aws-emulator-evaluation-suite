"""eventbridge-rule-filters-glue-job-name-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-filters-glue-job-name-positive"
GROUP = "event-propagation"
SERVICES = ["athena", "glue", "s3"]

GLUE_SERVICE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule pattern filtering detail.jobName to one specific Glue job: a
    synthetic event for a DIFFERENT job does not match the pattern (real TestEventPattern
    call), while the real SUCCEEDED event for the matching job is delivered to the target."""
    bucket = _create_bucket(ctx)
    role_arn = _create_glue_role(ctx, bucket)
    job_name = _create_pythonshell_job(ctx, role_arn, bucket, "print('ok')\n", "filter-job")
    other_job_name = ctx.unique_name("sim2real-other-job-")  # never created; used only for pattern probing

    queue_url, queue_arn = _create_queue(ctx)
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-filter-rule-")
    pattern = {
        "source": ["aws.glue"],
        "detail-type": ["Glue Job State Change"],
        "detail": {"jobName": [job_name]},
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    _set_queue_policy(ctx, queue_url, queue_arn, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target-1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))

    # Mismatch: a realistically-shaped Glue Job State Change event for a DIFFERENT job name
    # must not match this rule's pattern (exercised via the real EventBridge pattern engine).
    mismatched_event = {
        "version": "0",
        "id": "11111111-1111-1111-1111-111111111111",
        "detail-type": "Glue Job State Change",
        "source": "aws.glue",
        "account": "123456789012",
        "time": "2024-01-01T00:00:00Z",
        "region": ctx.region,
        "resources": [],
        "detail": {"jobName": other_job_name, "state": "SUCCEEDED", "jobRunId": "jr_0000000000000"},
    }
    match = events.test_event_pattern(EventPattern=json.dumps(pattern), Event=json.dumps(mismatched_event))
    assert match["Result"] is False

    # Match: the real job (same name as the pattern) actually running to SUCCEEDED is delivered.
    _run_job_to_success(ctx, job_name)

    message = _wait_for_matching_message(ctx, queue_url, job_name, timeout_s=180)
    assert message["detail"]["jobName"] == job_name
    assert message["detail"]["jobName"] != other_job_name


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
    # us-east-1 is CreateBucket's own default region and rejects an explicit LocationConstraint
    # for it, so the literal here names that one region, not a pin to it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    # No unconditional wait here: IAM role/policy propagation is eventually consistent, so the
    # bounded retry in _start_job_run (which reattempts on ClientError) is what actually absorbs it.
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
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run(ctx, job_name: str, timeout_s: float = 80.0) -> str:
    # StartJobRun can synchronously reject (e.g. throttling) while IAM's eventual-consistency
    # window is open: retry every 2 s to a deadline. A run that FAILS asynchronously on role
    # propagation is handled by _run_job_to_success's own retry.
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


_ROLE_NOT_READY_MARKER = "should be given assume role permissions"


def _run_job_to_success(ctx, job_name: str, max_attempts: int = 5, retry_wait_s: float = 15.0) -> None:
    """Starts the job and waits for a terminal state, retrying a fresh run only when the
    failure is IAM role/trust-policy propagation still catching up with Glue's execution
    backend -- confirmed against real AWS as
    "InvalidInputException: ... should be given assume role permissions for Glue Service" --
    which is genuine eventual consistency, not a guess. Any other terminal failure raises
    immediately, since that is a real defect rather than a timing race."""
    glue = ctx.client("glue")
    state, detail = None, None
    for attempt in range(max_attempts):
        run_id = _start_job_run(ctx, job_name)
        state = _wait_for_terminal_job_state(ctx, job_name, run_id, timeout_s=300)
        if state == "SUCCEEDED":
            return
        err = glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"].get("ErrorMessage", "")
        detail = f"{state}: {err}"
        if state == "FAILED" and _ROLE_NOT_READY_MARKER in err and attempt + 1 < max_attempts:
            time.sleep(retry_wait_s)
            continue
        break
    assert state == "SUCCEEDED", f"job {job_name} did not SUCCEED after retries: {detail}"


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-glue-evt-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.tag_queue(QueueUrl=url, Tags={"sim2real-check": CHECK})
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
