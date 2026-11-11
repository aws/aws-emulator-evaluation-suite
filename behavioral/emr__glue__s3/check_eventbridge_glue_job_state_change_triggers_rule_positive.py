"""eventbridge-glue-job-state-change-triggers-rule-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-glue-job-state-change-triggers-rule-positive"
GROUP = "event-propagation"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule matching 'Glue Job State Change' delivers the SUCCEEDED
    notification to its SQS target once a real Glue job run completes."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bucket = ctx.unique_name("sim2real-behav-gluejob-")
    _create_bucket(ctx, s3, bucket)
    script_key = "scripts/job.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=b"print('sim2real glue job ok')\n")

    role_arn, _role_name = _create_role(
        ctx,
        "glue.amazonaws.com",
        ["arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
    )

    job_name = ctx.unique_name("sim2real-behav-job-")
    _call_with_role_retry(
        lambda: glue.create_job(
            Name=job_name,
            Role=role_arn,
            Command={
                "Name": "pythonshell",
                "ScriptLocation": f"s3://{bucket}/{script_key}",
                "PythonVersion": "3.9",
            },
            MaxCapacity=0.0625,
            Timeout=5,
            Tags={"sim2real-check": CHECK},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    pattern = {
        "source": ["aws.glue"],
        "detail-type": ["Glue Job State Change"],
        "detail": {"jobName": [job_name], "state": ["SUCCEEDED"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    _allow_eventbridge_to_send(sqs, queue_url, queue_arn, rule_arn)

    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    def _start_and_wait_job_run():
        deadline = time.monotonic() + 60.0
        while True:
            try:
                rid = glue.start_job_run(JobName=job_name)["JobRunId"]
                break
            except ClientError as e:
                if (
                    e.response.get("Error", {}).get("Code") == "ConcurrentRunsExceededException"
                    and time.monotonic() < deadline
                ):
                    time.sleep(2)
                    continue
                raise
        state = _poll_until(
            lambda: glue.get_job_run(JobName=job_name, RunId=rid)["JobRun"]["JobRunState"],
            lambda s: s in ("SUCCEEDED", "FAILED", "ERROR", "TIMEOUT", "STOPPED"),
            timeout_s=300,
            interval_s=10,
            description="glue job run terminal state",
        )
        return rid, state

    run_id, final_state = _start_and_wait_job_run()
    # The Glue service role trust policy can lag IAM's own eventual-consistency window
    # even after get_role reports the role: the FIRST job run can fail at execution
    # time with "should be given assume role permissions for Glue Service" even though
    # create_job (a control-plane call) already succeeded. Retry the run itself.
    retry_deadline = time.monotonic() + 180.0
    while (
        final_state in ("FAILED", "ERROR")
        and time.monotonic() < retry_deadline
        and "assume role permissions"
        in (glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"].get("ErrorMessage") or "")
    ):
        time.sleep(2)
        run_id, final_state = _start_and_wait_job_run()

    assert final_state == "SUCCEEDED", (
        f"{glue.get_job_run(JobName=job_name, RunId=run_id)['JobRun'].get('ErrorMessage')} "
        f"(state={final_state})"
    )

    messages = _poll_until(
        lambda: _receive_all(sqs, queue_url),
        lambda msgs: len(msgs) > 0,
        timeout_s=120,
        interval_s=5,
        description="eventbridge delivery of Glue Job State Change to SQS",
    )
    body = json.loads(messages[0]["Body"])
    assert body["detail-type"] == "Glue Job State Change", (
        f"expected detail-type 'Glue Job State Change', got {body.get('detail-type')!r}"
    )
    assert body["source"] == "aws.glue", f"expected source 'aws.glue', got {body.get('source')!r}"
    assert body["detail"]["jobName"] == job_name, (
        f"expected detail.jobName {job_name!r}, got {body['detail'].get('jobName')!r}"
    )
    assert body["detail"]["state"] == "SUCCEEDED", (
        f"expected detail.state 'SUCCEEDED', got {body['detail'].get('state')!r}"
    )
    assert body["detail"]["jobRunId"] == run_id, (
        f"expected detail.jobRunId {run_id!r}, got {body['detail'].get('jobRunId')!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_role(
    ctx, trust_service: str, managed_policy_arns: list[str], inline_policy=None, policy_name="inline-policy"
):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if inline_policy:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
        )

    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["RoleName"],
        lambda n: n == role_name,
        timeout_s=30,
        interval_s=2,
        description="role visible via get_role",
    )
    return role_arn, role_name


def _call_with_role_retry(fn, timeout_s=120.0, interval_s=5.0):
    """IAM roles are eventually consistent; retry a create-with-role call while it is being
    rejected as not-yet-assumable, rather than sleeping a fixed guess."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_exc = e
            code = e.response.get("Error", {}).get("Code", "")
            if code in (
                "AccessDeniedException",
                "AccessDenied",
                "InvalidInputException",
                "InvalidInput",
            ):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _allow_eventbridge_to_send(sqs, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _receive_all(sqs, queue_url: str) -> list[dict[str, Any]]:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=2)
    return resp.get("Messages", [])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
