"""invoke-async-completion-event-delivered-via-eventbridge."""
from __future__ import annotations

import json
import struct
import time
import zlib

from behavioral_harness import tags

CHECK = "invoke-async-completion-event-delivered-via-eventbridge"
GROUP = "event-propagation"
SERVICES = ["bedrock-data-automation-runtime"]

# region-pinned: BDA's cross-region-inference profile ARN embeds a region-group suffix
# that differs by source region, so the mapping itself is the resource being addressed.
_PROFILE_SUFFIX_BY_REGION = {
    "us-east-1": "us.data-automation-v1",
    "us-west-2": "us.data-automation-v1",
    "us-east-2": "us.data-automation-v1",
    "ca-central-1": "na.data-automation-v1",
    "eu-central-1": "eu.data-automation-v1",
    "eu-west-1": "eu.data-automation-v1",
    "eu-west-2": "eu.data-automation-v1",
    "eu-south-2": "eu.data-automation-v1",
    "ap-south-1": "apac.data-automation-v1",
    "ap-southeast-2": "apac.data-automation-v1",
    "ap-northeast-1": "apac.data-automation-v1",
    "us-gov-west-1": "us-gov.data-automation-v1",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An InvokeDataAutomationAsync job with EventBridge notifications enabled emits a 'Bedrock Data
    Automation Job Succeeded' event (source aws.bedrock) carrying its job id, which an EventBridge
    rule delivers to an SQS queue.
    """
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-bda-events-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    rule_name = ctx.unique_name("sim2real-bda-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.bedrock"],
                "detail-type": [
                    "Bedrock Data Automation Job Created",
                    "Bedrock Data Automation Job Succeeded",
                    "Bedrock Data Automation Job Failed With Client Error",
                    "Bedrock Data Automation Job Failed With Service Error",
                ],
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]

    def _delete_rule():
        events.remove_targets(Rule=rule_name, Ids=["sim2real-bda-target"])
        events.delete_rule(Name=rule_name)

    ctx.on_cleanup(_delete_rule)

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
    events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-bda-target", "Arn": queue_arn}])

    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)

    invocation_arn = bda.invoke_data_automation_async(
        inputConfiguration={"s3Uri": input_uri},
        outputConfiguration={"s3Uri": output_uri},
        dataAutomationProfileArn=profile_arn,
        dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
        notificationConfiguration={"eventBridgeConfiguration": {"eventBridgeEnabled": True}},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["invocationArn"]

    job_id = invocation_arn.rsplit("/", 1)[1]
    matched = _poll_for_event(
        sqs,
        queue_url,
        job_id,
        "Bedrock Data Automation Job Succeeded",
        timeout_s=230.0,
    )
    assert matched is not None, (
        f"no 'Bedrock Data Automation Job Succeeded' EventBridge event for job_id "
        f"{job_id} (invocation {invocation_arn}) was delivered to the SQS target "
        "within the poll window"
    )
    assert matched["source"] == "aws.bedrock"
    assert matched["detail-type"] == "Bedrock Data Automation Job Succeeded"
    assert matched["detail"]["job_id"] == job_id


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name,
        projectStage="LIVE",
        standardOutputConfiguration={},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    project_arn = resp["projectArn"]
    ctx.on_cleanup(lambda: ctrl.delete_data_automation_project(projectArn=project_arn))
    return project_arn


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _profile_arn(ctx):
    suffix = _PROFILE_SUFFIX_BY_REGION.get(ctx.region)
    if suffix is None:
        raise AssertionError(
            f"region {ctx.region} is not one of the documented BDA cross-region-inference "
            "source regions; cannot construct a data-automation-profile ARN"
        )
    return f"arn:aws:bedrock:{ctx.region}:{_account_id(ctx)}:data-automation-profile/{suffix}"


def _minimal_png_bytes():
    return _generate_png_bytes()


def _generate_png_bytes(width=64, height=64, rgb=(90, 180, 60)):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(
            ">I", zlib.crc32(tag + data) & 0xFFFFFFFF
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = bytes(rgb) * width
    raw = (b"\x00" + row) * height
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_input_bucket_and_object(ctx, s3):
    bucket = ctx.unique_name("sim2real-bda-").replace("_", "-").lower()
    if ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


def _poll_for_event(sqs, queue_url, invocation_arn, detail_type, timeout_s=230.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            raw = json.dumps(body)
            if invocation_arn in raw and body.get("detail-type") == detail_type:
                return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

