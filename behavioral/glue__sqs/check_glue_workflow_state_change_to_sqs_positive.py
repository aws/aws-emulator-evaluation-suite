"""glue-workflow-state-change-to-sqs-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "glue-workflow-state-change-to-sqs-positive"
GROUP = "event-propagation"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue workflow run surfaces as its job's "Glue Job State Change" event, delivered to SQS.

    Glue has no workflow-level detail-type; GetWorkflowRun confirms the delivered jobRunId is one
    of this workflow run's own job runs.
    """
    bucket = _create_glue_script_bucket(ctx)
    script_uri = _upload_job_script(ctx, bucket, "print('sim2real-glue-workflow-ok')\n")
    role_arn = _create_glue_job_role(ctx, bucket)
    job_name = _create_pythonshell_job(ctx, role_arn, script_uri)

    glue = ctx.client("glue")
    workflow_name = ctx.unique_name("sim2real-glue-wf-")
    glue.create_workflow(Name=workflow_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: glue.delete_workflow(Name=workflow_name))

    trigger_name = ctx.unique_name("sim2real-glue-trig-")
    glue.create_trigger(
        Name=trigger_name,
        WorkflowName=workflow_name,
        Type="ON_DEMAND",
        Actions=[{"JobName": job_name}],
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=trigger_name))

    rule_name, rule_arn = _create_rule(
        ctx,
        {
            "source": ["aws.glue"],
            "detail-type": ["Glue Job State Change"],
            "detail": {"jobName": [job_name], "state": ["SUCCEEDED"]},
        },
    )
    queue_url, queue_arn = _create_queue(ctx)
    _set_queue_policy_for_rule(ctx, queue_url, queue_arn, rule_arn)
    _put_sqs_target(ctx, rule_name, queue_arn)

    _start_trigger_with_retry(ctx, trigger_name)

    body = _drain_queue_until_match(
        ctx,
        queue_url,
        lambda b: isinstance(b, dict) and b.get("detail", {}).get("jobName") == job_name,
        timeout_s=480.0,
    )
    assert body["detail"]["state"] == "SUCCEEDED", (
        f"expected delivered event state SUCCEEDED, got {body['detail']['state']!r}"
    )
    delivered_job_run_id = body["detail"]["jobRunId"]

    run_id = _poll_until(
        lambda: (glue.get_workflow_runs(Name=workflow_name).get("Runs") or [None])[0],
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="workflow run visible",
    )["WorkflowRunId"]

    workflow_run = _poll_until(
        lambda: glue.get_workflow_run(
            Name=workflow_name, RunId=run_id, IncludeGraph=True
        )["Run"],
        lambda r: r["Status"] in ("COMPLETED", "ERROR", "STOPPED"),
        timeout_s=300.0,
        interval_s=5.0,
        description="workflow run terminal status",
    )
    assert workflow_run["Status"] == "COMPLETED", (
        f"expected workflow run terminal status COMPLETED, got {workflow_run['Status']!r}"
    )

    job_run_ids_in_workflow = [
        jr["Id"]
        for node in workflow_run["Graph"]["Nodes"]
        if node["Type"] == "JOB"
        for jr in node.get("JobDetails", {}).get("JobRuns", [])
    ]
    assert delivered_job_run_id in job_run_ids_in_workflow, (
        f"expected delivered jobRunId {delivered_job_run_id!r} among this workflow's "
        f"own job runs {job_run_ids_in_workflow!r} -- the event must correspond to "
        "this specific workflow execution"
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


def _create_pythonshell_job(
    ctx, role_arn: str, script_uri: str, timeout_s=60.0, interval_s=5.0
) -> str:
    # A freshly created role/policy is not immediately assumable everywhere; retry
    # bounded on that IAM propagation delay instead of a blind sleep before create.
    glue = ctx.client("glue")
    job_name = ctx.unique_name("sim2real-glue-job-")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
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
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    assert last_err is not None
    raise last_err


def _start_trigger_with_retry(ctx, trigger_name: str, timeout_s=90.0, interval_s=5.0) -> None:
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            glue.start_trigger(Name=trigger_name)
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    assert last_err is not None
    raise last_err



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
