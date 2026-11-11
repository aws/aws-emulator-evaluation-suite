"""media-insights-pipeline-configuration-update-persists."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "media-insights-pipeline-configuration-update-persists"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMediaInsightsPipelineConfiguration replaces Elements/ResourceAccessRoleArn and the
    change is visible on a subsequent Get, with UpdatedTimestamp advancing."""
    chime = ctx.client("chime-sdk-media-pipelines")
    role_arn = _create_iam_role_for_media_insights(ctx)
    other_role_arn = _create_iam_role_for_media_insights(ctx)
    sink_element = _create_kinesis_sink_element(ctx)
    name = ctx.unique_name("sim2real-micfg-")

    created = _create_config_with_retry(
        ctx,
        chime,
        MediaInsightsPipelineConfigurationName=name,
        ResourceAccessRoleArn=role_arn,
        Elements=_transcribe_elements("en-US") + [sink_element],
        Tags=[{"Key": "sim2real-env", "Value": "test"}],
    )["MediaInsightsPipelineConfiguration"]
    # Identifier accepts the configuration's name or ARN, never the GUID
    # MediaInsightsPipelineConfigurationId - passing the id 404s every subsequent call
    # (observed on real AWS: Update raised NotFoundException "Unable to find the
    # requested identifier" against the id for the full retry deadline).
    identifier = name
    ctx.on_cleanup(
        lambda: chime.delete_media_insights_pipeline_configuration(Identifier=identifier)
    )
    original_updated = created["UpdatedTimestamp"]

    updated = _update_config_with_retry(
        ctx,
        chime,
        Identifier=identifier,
        ResourceAccessRoleArn=other_role_arn,
        Elements=_transcribe_elements("es-US") + [sink_element],
    )["MediaInsightsPipelineConfiguration"]

    assert updated["ResourceAccessRoleArn"] == other_role_arn, (
        f"expected updated ResourceAccessRoleArn={other_role_arn!r}, "
        f"got {updated['ResourceAccessRoleArn']!r}"
    )
    updated_lang = updated["Elements"][0]["AmazonTranscribeProcessorConfiguration"]["LanguageCode"]
    assert updated_lang == "es-US", f"expected updated LanguageCode='es-US', got {updated_lang!r}"
    assert updated["UpdatedTimestamp"] >= original_updated, (
        f"expected UpdatedTimestamp to advance: original={original_updated!r}, "
        f"updated={updated['UpdatedTimestamp']!r}"
    )

    fetched = _get_config_tolerant(chime, identifier)
    assert fetched["ResourceAccessRoleArn"] == other_role_arn, (
        f"independent get: expected ResourceAccessRoleArn={other_role_arn!r}, "
        f"got {fetched['ResourceAccessRoleArn']!r}"
    )
    fetched_lang = fetched["Elements"][0]["AmazonTranscribeProcessorConfiguration"]["LanguageCode"]
    assert fetched_lang == "es-US", (
        f"independent get: expected LanguageCode='es-US', got {fetched_lang!r}"
    )


def _create_kinesis_sink_element(ctx) -> dict:
    """CreateMediaInsightsPipelineConfiguration requires at least one sink element for a
    transcribe processor; real-time transcription insights require a KinesisDataStreamSink
    (per AWS docs, "Combining transcription with recording sinks")."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-micfg-sink-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real-env": "test"}
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
        Tags=[{"Key": "sim2real-env", "Value": "test"}],
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
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_insights_pipeline_configuration(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NotFoundException", "ForbiddenException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _update_config_with_retry(ctx, chime, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """IAM role visibility to Chime is eventually consistent; retry the update call itself
    (not a bare sleep) until the new role is recognized or the timeout expires. Also retry
    a transient NotFoundException right after create (the config itself not yet visible)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.update_media_insights_pipeline_configuration(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NotFoundException", "ForbiddenException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _get_config_tolerant(chime, identifier: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> dict:
    """A configuration just created/updated may not be immediately visible to Get (eventual
    consistency); poll through a short window of NotFoundException before giving up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.get_media_insights_pipeline_configuration(Identifier=identifier)[
                "MediaInsightsPipelineConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
