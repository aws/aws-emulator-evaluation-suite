"""glue-job-state-change-detail-fields-preserved-in-sqs."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-job-state-change-detail-fields-preserved-in-sqs"
GROUP = "data-format"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The jobName, jobRunId and state fields of the real "Glue Job State Change"
    EventBridge detail are carried verbatim, byte-for-byte, into the SQS message body
    -- EventBridge->SQS delivery is raw (no envelope wrapping, unlike SNS->SQS)."""
    bucket = _create_glue_script_bucket(ctx)
    script_uri = _upload_job_script(ctx, bucket, "print('sim2real-glue-format-ok')\n")
    role_arn = _create_glue_job_role(ctx, bucket)
    job_name = _create_pythonshell_job(ctx, role_arn, script_uri)

    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["aws.glue"],
            "detail-type": ["Glue Job State Change"],
            "detail": {"jobName": [job_name]},
        },
    )
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, queue_url, queue_arn, rule_arn)
    _put_sqs_target(ctx, rule_name, queue_arn)

    job_run_id = _run_job_until_succeeded(ctx, job_name)

    # Glue emits a "Glue Job State Change" event at every transition (STARTING, RUNNING,
    # then a terminal state) -- all match on jobName alone, so the predicate must also
    # pin the terminal state or it grabs the first (non-terminal) event instead.
    raw_body, envelope = _drain_queue_until_match_raw(
        ctx,
        queue_url,
        lambda b: (
            isinstance(b, dict)
            and b.get("detail", {}).get("jobName") == job_name
            and b.get("detail", {}).get("state") == "SUCCEEDED"
        ),
        timeout_s=480.0,
    )
    # The SQS message body is the EventBridge event JSON itself -- no SNS-style
    # {"Type": "Notification", "Message": ...} envelope wraps it.
    assert "Type" not in envelope and "Message" not in envelope, (
        f"expected a raw EventBridge event, got an SNS-style envelope: {envelope!r}"
    )
    assert envelope["detail"]["jobName"] == job_name, (
        f"expected jobName {job_name!r}, got {envelope['detail'].get('jobName')!r}"
    )
    assert envelope["detail"]["jobRunId"] == job_run_id, (
        f"expected jobRunId {job_run_id!r}, got {envelope['detail'].get('jobRunId')!r}"
    )
    assert envelope["detail"]["state"] == "SUCCEEDED", (
        f"expected state SUCCEEDED, got {envelope['detail'].get('state')!r}"
    )
    # Field values must be preserved as plain strings, not re-encoded/escaped.
    assert isinstance(raw_body, str) and job_run_id in raw_body and job_name in raw_body, (
        f"expected raw body to contain {job_run_id!r} and {job_name!r} verbatim, got {raw_body!r}"
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
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))
    return job_name


def _start_job_run(ctx, job_name: str, timeout_s=90.0, interval_s=5.0) -> str:
    """Retries StartJobRun because the just-created role has not necessarily propagated
    through IAM yet; Glue answers with a ClientError until it has."""
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return glue.start_job_run(JobName=job_name)["JobRunId"]
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    assert last_err is not None
    raise last_err


def _run_job_until_succeeded(ctx, job_name: str, timeout_s=300.0) -> str:
    """Starts the job and waits for its own reported terminal state -- independent of the
    EventBridge/SQS path this check exists to exercise, so a failure here is separated from
    "the event never arrived".

    StartJobRun itself does not surface IAM's assume-role-propagation delay (it accepts and
    returns a RunId even when the role cannot yet be assumed); the failure only shows up
    asynchronously, as a terminal FAILED run whose ErrorMessage names the missing assume-role
    permission. That is retried here -- by starting a fresh run, not by waiting longer on the
    same one -- exactly like _start_job_run's own ClientError retry, and for the same reason.
    """
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_run: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        job_run_id = _start_job_run(ctx, job_name)

        def probe():
            return glue.get_job_run(JobName=job_name, RunId=job_run_id)["JobRun"]

        last_run = _poll_until(
            probe,
            lambda r: r["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"),
            timeout_s=max(deadline - time.monotonic(), 1.0),
            interval_s=5.0,
            description="glue job run reaching a terminal state",
        )
        if last_run["JobRunState"] == "SUCCEEDED":
            return job_run_id
        if "assume role permissions" not in (last_run.get("ErrorMessage") or ""):
            break
        time.sleep(5.0)
    raise AssertionError(
        f"expected a job run to SUCCEED, got {last_run['JobRunState']!r}: "
        f"{last_run.get('ErrorMessage')!r}"
    )


def _create_rule(ctx, event_pattern: dict[str, Any]) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-glue-rule-")
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, resp["RuleArn"]


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-glue-evt-")
    url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
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


def _drain_queue_until_match_raw(
    ctx, queue_url: str, predicate, timeout_s=300.0, interval_s=5.0
):
    """Like _drain_queue_until_match, but also returns the raw (un-decoded) message
    body string so we can assert the fields were not re-serialized/altered in transit."""
    sqs = ctx.client("sqs")
    found: dict[str, Any] = {"raw": None, "body": None}

    def probe():
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            raw = m["Body"]
            try:
                body = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                body = raw
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if found["body"] is None and predicate(body):
                found["raw"] = raw
                found["body"] = body
        return found["body"]

    _poll_until(
        probe,
        lambda v: v is not None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="matching SQS message",
    )
    return found["raw"], found["body"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
