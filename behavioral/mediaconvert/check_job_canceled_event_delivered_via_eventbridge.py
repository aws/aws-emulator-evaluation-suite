"""job-canceled-event-delivered-via-eventbridge."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "job-canceled-event-delivered-via-eventbridge"
GROUP = "event-propagation"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A job canceled while its queue is PAUSED reaches CANCELED but emits no Job State Change event,
    while a job that starts on an ACTIVE queue and fails delivers its ERROR event from aws.mediaconvert,
    with its jobId and status, through the same rule to SQS."""
    # MediaConvert emits job events once a job begins processing:
    # https://docs.aws.amazon.com/mediaconvert/latest/ug/how-mediaconvert-jobs-progress.html
    mc = ctx.client("mediaconvert")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mc-evt-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    rule_name = ctx.unique_name("sim2real-mc-rule-")
    pattern = json.dumps(
        {
            "source": ["aws.mediaconvert"],
            "detail-type": ["MediaConvert Job State Change"],
        }
    )
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=pattern, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    pt_resp = events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])
    assert pt_resp.get("FailedEntryCount", 0) == 0, f"PutTargets failed: {pt_resp.get('FailedEntries')}"
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sqs-target"]))

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
    # SQS resource-policy changes and EventBridge rule/target wiring are eventually consistent:
    # a delivery attempted before the policy propagates is refused and EventBridge retries it
    # with backoff, so the event poll below allows for those retries rather than sleeping first.

    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED", Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))
    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    job = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)["Job"]
    mc.cancel_job(Id=job["Id"])

    # The job's own state machine really reaches CANCELED (verified directly against the
    # control plane) regardless of whether the async EventBridge hop below is observable in
    # this environment within a bounded window.
    deadline = time.monotonic() + 30.0
    job_status = None
    while time.monotonic() < deadline:
        job_status = mc.get_job(Id=job["Id"])["Job"]["Status"]
        if job_status == "CANCELED":
            break
        time.sleep(3.0)
    assert job_status == "CANCELED", f"job never reached CANCELED, saw {job_status!r}"

    active_queue = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=active_queue, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _delete_queue_when_idle(mc, active_queue))
    failing = _create_job_with_retry(mc, Role=role_arn, Queue=active_queue, Settings=settings)["Job"]

    seen = _poll_for_job_event(sqs, queue_url, failing["Id"], timeout_s=900.0)
    event = seen.pop("event")
    detail = event["detail"]
    assert detail["status"] == "ERROR", f"expected detail.status ERROR, got {detail.get('status')!r}"
    assert detail["jobId"] == failing["Id"], f"expected detail.jobId {failing['Id']!r}, got {detail.get('jobId')!r}"
    assert event["source"] == "aws.mediaconvert", f"expected source aws.mediaconvert, got {event.get('source')!r}"
    # The silence is an absence: keep draining for a window after the control's event arrived, so
    # an event from the canceled job still in flight would be seen.
    for job_id, statuses in _drain_job_statuses(sqs, queue_url, 120.0).items():
        seen.setdefault(job_id, []).extend(statuses)
    assert job["Id"] not in seen, f"the job canceled before it began processing emitted {seen[job['Id']]}"


def _output_groups(output_uri: str) -> list:
    return [
        {
            "Name": "File Group",
            "OutputGroupSettings": {
                "Type": "FILE_GROUP_SETTINGS",
                "FileGroupSettings": {"Destination": output_uri},
            },
            "Outputs": [
                {
                    "ContainerSettings": {"Container": "MP4"},
                    "VideoDescription": {
                        "CodecSettings": {
                            "Codec": "H_264",
                            "H264Settings": {
                                "RateControlMode": "QVBR",
                                "QvbrSettings": {"QvbrQualityLevel": 7},
                                "MaxBitrate": 5000000,
                                "SceneChangeDetect": "ENABLED",
                            },
                        }
                    },
                }
            ],
        }
    ]


def _job_settings(input_uri: str, output_uri: str) -> dict:
    return {"Inputs": [{"FileInput": input_uri}], "OutputGroups": _output_groups(output_uri)}


def _create_mediaconvert_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mc-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "mediaconvert.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return arn


def _create_job_with_retry(mc, *, timeout_s: float = 45.0, interval_s: float = 3.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mc.create_job(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ForbiddenException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_queue_when_idle(mc, name: str, timeout_s: float = 180.0) -> None:
    """Teardown: a queue whose job only just failed is briefly "in use" (ConflictException)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            mc.delete_queue(Name=name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(10.0)


def _drain_job_statuses(sqs, queue_url: str, window_s: float) -> dict:
    """Every job's event statuses that arrive on the queue within ``window_s``, keyed by job id."""
    deadline = time.monotonic() + window_s
    seen: dict = {}
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            detail = body.get("detail", {})
            seen.setdefault(detail.get("jobId"), []).append(detail.get("status"))
    return seen


def _poll_for_job_event(sqs, queue_url: str, job_id: str, timeout_s: float) -> dict:
    """Drain the queue until ``job_id``'s ERROR event arrives; return every other job's statuses
    seen on the way, keyed by job id, with that event under "event"."""
    deadline = time.monotonic() + timeout_s
    seen: dict = {}
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            detail = body.get("detail", {})
            if detail.get("jobId") == job_id and detail.get("status") == "ERROR":
                return {**seen, "event": body}
            seen.setdefault(detail.get("jobId"), []).append(detail.get("status"))
    raise AssertionError(f"no ERROR event for job {job_id} within {timeout_s}s; saw {seen}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

