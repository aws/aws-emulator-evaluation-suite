"""media-insights-pipeline-configuration-create-get-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "media-insights-pipeline-configuration-create-get-roundtrip"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMediaInsightsPipelineConfiguration persists Elements/RealTimeAlertConfiguration
    exactly as given, and GetMediaInsightsPipelineConfiguration returns the same values."""
    chime = ctx.client("chime-sdk-media-pipelines")
    role_arn = _create_iam_role_for_media_insights(ctx)
    sink_element = _create_kinesis_sink_element(ctx)
    name = ctx.unique_name("sim2real-micfg-")

    created = _create_config_with_retry(
        ctx,
        chime,
        MediaInsightsPipelineConfigurationName=name,
        ResourceAccessRoleArn=role_arn,
        Elements=_transcribe_elements("en-US") + [sink_element],
        RealTimeAlertConfiguration={"Disabled": True},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["MediaInsightsPipelineConfiguration"]
    config_arn = created["MediaInsightsPipelineConfigurationArn"]
    ctx.on_cleanup(
        lambda: chime.delete_media_insights_pipeline_configuration(Identifier=config_arn)
    )

    assert created["MediaInsightsPipelineConfigurationName"] == name, (
        f"create echo name mismatch: expected {name!r}, got "
        f"{created['MediaInsightsPipelineConfigurationName']!r}"
    )
    assert created["ResourceAccessRoleArn"] == role_arn, (
        f"create echo role mismatch: expected {role_arn!r}, got {created['ResourceAccessRoleArn']!r}"
    )
    assert len(created["Elements"]) == 2, (
        f"expected 2 elements on create, got {len(created['Elements'])}: {created['Elements']!r}"
    )
    types = {e["Type"] for e in created["Elements"]}
    assert types == {"AmazonTranscribeProcessor", "KinesisDataStreamSink"}, (
        f"create element types mismatch: expected "
        f"{{'AmazonTranscribeProcessor', 'KinesisDataStreamSink'}}, got {types!r}"
    )

    fetched = _get_config_tolerant(chime, config_arn)
    assert fetched["MediaInsightsPipelineConfigurationName"] == name, (
        f"get echo name mismatch: expected {name!r}, got "
        f"{fetched['MediaInsightsPipelineConfigurationName']!r}"
    )
    assert fetched["ResourceAccessRoleArn"] == role_arn, (
        f"get echo role mismatch: expected {role_arn!r}, got {fetched['ResourceAccessRoleArn']!r}"
    )
    fetched_transcribe = next(
        e for e in fetched["Elements"] if e["Type"] == "AmazonTranscribeProcessor"
    )
    fetched_language = fetched_transcribe["AmazonTranscribeProcessorConfiguration"]["LanguageCode"]
    assert fetched_language == "en-US", (
        f"get transcribe language mismatch: expected 'en-US', got {fetched_language!r}"
    )
    fetched_disabled = fetched["RealTimeAlertConfiguration"]["Disabled"]
    assert fetched_disabled is True, (
        f"get RealTimeAlertConfiguration.Disabled mismatch: expected True, got {fetched_disabled!r}"
    )


def _create_kinesis_sink_element(ctx) -> dict:
    """CreateMediaInsightsPipelineConfiguration requires at least one sink element for a
    transcribe processor; real-time transcription insights require a KinesisDataStreamSink
    (per AWS docs, "Combining transcription with recording sinks")."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-micfg-sink-")
    kinesis.create_stream(
        StreamName=stream_name,
        ShardCount=1,
        Tags={"sim2real-check": CHECK},
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


def _transcribe_elements(language_code: str) -> list:
    return [
        {
            "Type": "AmazonTranscribeProcessor",
            "AmazonTranscribeProcessorConfiguration": {"LanguageCode": language_code},
        }
    ]


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


def _get_config_tolerant(chime, config_arn: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> dict:
    """A configuration just created may not be immediately visible to Get (eventual
    consistency); poll through a short window of NotFoundException before giving up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.get_media_insights_pipeline_configuration(Identifier=config_arn)[
                "MediaInsightsPipelineConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_config_with_retry(ctx, chime, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """IAM role visibility to Chime is eventually consistent; retry the create call itself
    (not a bare sleep) until the role is recognized or the timeout expires."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_insights_pipeline_configuration(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NotFoundException", "ForbiddenException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


