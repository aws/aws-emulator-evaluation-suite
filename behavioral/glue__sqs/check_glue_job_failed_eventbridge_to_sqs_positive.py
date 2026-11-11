"""glue-job-failed-eventbridge-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-job-failed-eventbridge-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real Glue pythonshell job that FAILS (nonzero exit) emits a "Glue Job State
    Change" event with state FAILED that is delivered to SQS via an EventBridge rule."""
    bucket = _create_glue_script_bucket(ctx)
    script_uri = _upload_job_script(
        ctx, bucket, "import sys\nprint('sim2real-glue-job-failing')\nsys.exit(1)\n"
    )
    role_arn = _create_glue_job_role(ctx, bucket)
    job_name = _create_pythonshell_job(ctx, role_arn, script_uri)

    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["aws.glue"],
            "detail-type": ["Glue Job State Change"],
            "detail": {"jobName": [job_name], "state": ["FAILED"]},
        },
    )
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, queue_url, queue_arn, rule_arn)
    _put_sqs_target(ctx, rule_name, queue_arn)

    job_run_id = _start_job_run_with_retry(ctx, job_name)

    body = _drain_queue_until_match(
        ctx,
        queue_url,
        lambda b: isinstance(b, dict) and b.get("detail", {}).get("jobName") == job_name,
        timeout_s=480.0,
    )
    assert body["source"] == "aws.glue", f"expected source aws.glue, got {body['source']!r}"
    assert body["detail-type"] == "Glue Job State Change", (
        f"expected detail-type 'Glue Job State Change', got {body['detail-type']!r}"
    )
    assert body["detail"]["state"] == "FAILED", (
        f"expected state FAILED, got {body['detail']['state']!r}"
    )
    assert body["detail"]["jobRunId"] == job_run_id, (
        f"expected jobRunId {job_run_id!r}, got {body['detail']['jobRunId']!r}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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


def _create_glue_script_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-scripts-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_job_script(ctx, bucket: str, contents: str) -> str:
    s3 = ctx.client("s3")
    key = "scripts/job.py"
    s3.put_object(Bucket=bucket, Key=key, Body=contents.encode("utf-8"))
    return f"s3://{bucket}/{key}"


def _create_glue_job_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    )

    inline_name = "sim2real-glue-s3-access"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
    )
    return role["Arn"]


def _create_pythonshell_job(ctx, role_arn: str, script_uri: str) -> str:
    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    glue.create_job(
        Name=job_name,
        Role=role_arn,
        Command={
            "Name": "pythonshell",
            "ScriptLocation": script_uri,
            "PythonVersion": "3.9",
        },
        GlueVersion="3.0",
        MaxCapacity=0.0625,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run_with_retry(ctx, job_name: str, timeout_s=90.0, interval_s=5.0) -> str:
    """Bounded retry absorbs IAM role trust-policy propagation lag: Glue rejects
    StartJobRun with the role until it has propagated, which is not independently
    observable, so a fixed sleep before this point would only guess at the delay."""
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    assert last_err is not None, "retry loop exited without ever calling StartJobRun"
    raise last_err


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-rule-")
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-glue-evt-")
    url = sqs.create_queue(QueueName=queue_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _set_queue_policy_for_rule(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _put_sqs_target(ctx, rule_name: str, queue_arn: str) -> None:
    events = ctx.client("events")
    target_id = "sim2real-target"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _drain_queue_until_match(ctx, queue_url: str, predicate, timeout_s=300.0, interval_s=5.0):
    sqs = ctx.client("sqs")
    found: dict[str, Any] = {"msg": None}

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found["msg"] is None and predicate(body):
                found["msg"] = body
        return found["msg"]

    _poll_until(
        probe,
        lambda v: v is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="matching SQS message",
    )
    return found["msg"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
