"""create-media-insights-pipeline-configuration-conflicting-pii-settings-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-media-insights-pipeline-configuration-conflicting-pii-settings-accepted"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AmazonTranscribeProcessorConfiguration accepts ContentIdentificationType and ContentRedactionType
    set together, and a read of the created configuration (addressed by ARN) shows both still PII:
    AWS applies no create-time mutual-exclusion check for that pair.
    """
    chime = ctx.client("chime-sdk-media-pipelines")
    role_arn = _create_iam_role_for_media_insights(ctx)
    sink_element = _create_kinesis_sink_element(ctx)
    name = ctx.unique_name("sim2real-micfg-bothpii-")

    created = _create_config_with_retry(
        ctx,
        chime,
        MediaInsightsPipelineConfigurationName=name,
        ResourceAccessRoleArn=role_arn,
        Elements=[
            {
                "Type": "AmazonTranscribeProcessor",
                "AmazonTranscribeProcessorConfiguration": {
                    "LanguageCode": "en-US",
                    "ContentIdentificationType": "PII",
                    "ContentRedactionType": "PII",
                },
            },
            sink_element,
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["MediaInsightsPipelineConfiguration"]
    config_arn = created["MediaInsightsPipelineConfigurationArn"]
    ctx.on_cleanup(
        lambda: chime.delete_media_insights_pipeline_configuration(Identifier=config_arn)
    )
    assert created["MediaInsightsPipelineConfigurationName"] == name, (
        f"expected {name!r}, got {created['MediaInsightsPipelineConfigurationName']!r}"
    )

    # It is not merely accepted-and-discarded: the configuration is listed under its own name.
    listed = [
        item
        for item in _list_all_configs(chime)
        if item["MediaInsightsPipelineConfigurationName"] == name
    ]
    assert len(listed) == 1, (
        f"expected exactly one listed configuration named {name!r}, got {listed!r}"
    )

    # Terminal read: an independent GetMediaInsightsPipelineConfiguration at the destination,
    # not the create response's own echo, is what proves BOTH settings persisted.
    fetched = _get_config_tolerant(chime, config_arn)
    fetched_transcribe = next(
        e for e in fetched["Elements"] if e["Type"] == "AmazonTranscribeProcessor"
    )
    fetched_pii = fetched_transcribe["AmazonTranscribeProcessorConfiguration"]
    assert fetched_pii.get("ContentIdentificationType") == "PII", f"actual: {fetched_pii}"
    assert fetched_pii.get("ContentRedactionType") == "PII", f"actual: {fetched_pii}"
    assert fetched_pii.get("LanguageCode") == "en-US", f"actual: {fetched_pii}"


# ===== helpers =====
def _create_kinesis_sink_element(ctx) -> dict:
    """CreateMediaInsightsPipelineConfiguration requires at least one sink element for a
    transcribe processor; real-time transcription insights require a KinesisDataStreamSink
    (per AWS docs, "Combining transcription with recording sinks")."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-micfg-sink-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    stream_arn = _wait_stream_active(kinesis, stream_name)
    return {
        "Type": "KinesisDataStreamSink",
        "KinesisDataStreamSinkConfiguration": {"InsightsTarget": stream_arn},
    }


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        if time.monotonic() >= deadline:
            raise TimeoutError(f"stream {stream_name} never became ACTIVE: {desc['StreamStatus']}")
        time.sleep(interval_s)


def _create_iam_role_for_media_insights(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-chimepipe-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "mediapipelines.chime.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:PutRecord",
                    "kinesis:PutRecords",
                    "kinesis:DescribeStream",
                    "kinesis:DescribeStreamSummary",
                    "kinesis:GetRecords",
                    "kinesis:GetShardIterator",
                    "kinesis:ListShards",
                    "kinesis:ListStreams",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=name, PolicyName="sim2real-kinesis-access", PolicyDocument=json.dumps(access_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-kinesis-access"))
    return role["Arn"]


def _create_config_with_retry(ctx, chime, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """Retry only while the freshly-created IAM role is not yet visible to Chime (ForbiddenException
    "Service does not have permission to invoke role"); every other error, in particular a
    BadRequestException for the PII pair, propagates immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_insights_pipeline_configuration(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NotFoundException", "ForbiddenException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _list_all_configs(chime) -> list:
    out = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = chime.list_media_insights_pipeline_configurations(**kwargs)
        out.extend(resp.get("MediaInsightsPipelineConfigurations", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return out


def _get_config_tolerant(chime, config_id: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> dict:
    """A configuration just created may not be immediately visible to Get (eventual
    consistency); poll through a short window of NotFoundException before giving up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.get_media_insights_pipeline_configuration(Identifier=config_id)[
                "MediaInsightsPipelineConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
