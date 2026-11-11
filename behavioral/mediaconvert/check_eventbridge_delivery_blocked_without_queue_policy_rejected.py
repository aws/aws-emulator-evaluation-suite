"""eventbridge-delivery-blocked-without-queue-policy-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-delivery-blocked-without-queue-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A MediaConvert job state change event for a job that fails to ERROR is not delivered to an SQS
    target whose policy does not grant events.amazonaws.com sqs:SendMessage; after the grant, the same
    rule delivers a second job's ERROR event with its jobId and status."""
    # MediaConvert emits job events once a job begins processing:
    # https://docs.aws.amazon.com/mediaconvert/latest/ug/how-mediaconvert-jobs-progress.html
    mc = ctx.client("mediaconvert")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-mc-evt-"), tags={"purpose": "behavioral-check"}
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
        Name=rule_name, EventPattern=pattern, Tags=[{"Key": "purpose", "Value": "behavioral-check"}]
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    pt_resp = events.put_targets(Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue_arn}])
    assert pt_resp.get("FailedEntryCount", 0) == 0, f"PutTargets failed: {pt_resp.get('FailedEntries')}"
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sqs-target"]))

    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: _delete_queue_when_idle(mc, queue_name))
    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    # no SQS queue policy granting events.amazonaws.com has been set yet
    job1 = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)["Job"]
    assert _wait_job_terminal(mc, job1["Id"]) == "ERROR", f"job1 {job1['Id']} did not fail to ERROR"

    found1 = _poll_for_job_event(sqs, queue_url, job1["Id"], timeout_s=45.0)
    assert found1 is None, "event was delivered to SQS despite no resource policy granting access"

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
    # SQS resource-policy propagation to the delivery path is eventually consistent: a delivery
    # refused before it propagates is retried by EventBridge with backoff, which the bounded poll
    # below allows for.

    job2 = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)["Job"]

    # Isolate a control-plane failure (job never actually failed) from a delivery-pipeline
    # failure (failed, but the EventBridge notification never arrives) before trusting the SQS
    # poll below to mean the latter.
    job2_status = _wait_job_terminal(mc, job2["Id"])
    assert job2_status == "ERROR", f"job2 never reached ERROR on the control plane, saw {job2_status!r}"

    found2 = _poll_for_job_event(sqs, queue_url, job2["Id"], timeout_s=900.0)
    if found2 is None:
        raise AssertionError(
            "the core boundary (no queue policy => no delivery) was verified above; the "
            "positive-control redelivery after granting the queue policy was not observed on "
            "SQS within the bounded poll window -- closed by an environment where "
            "MediaConvert-to-EventBridge delivery latency for this account/region is within "
            "the test window"
        )
    assert found2["detail"]["status"] == "ERROR", (
        f"expected delivered event status ERROR, got {found2['detail'].get('status')!r}"
    )
    assert found2["detail"]["jobId"] == job2["Id"], (
        f"expected delivered event jobId {job2['Id']!r}, got {found2['detail'].get('jobId')!r}"
    )


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
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
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


def _wait_job_terminal(mc, job_id: str, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = mc.get_job(Id=job_id)["Job"]["Status"]
        if status in ("ERROR", "COMPLETE", "CANCELED"):
            return status
        time.sleep(3.0)
    return status


def _poll_for_job_event(sqs, queue_url: str, job_id: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    seen_statuses = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = {}
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            detail = body.get("detail", {})
            if detail.get("jobId") == job_id:
                seen_statuses.append(detail.get("status"))
                if detail.get("status") == "ERROR":
                    return body
    if seen_statuses:
        raise AssertionError(f"job {job_id} emitted events but never ERROR: saw {seen_statuses}")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
