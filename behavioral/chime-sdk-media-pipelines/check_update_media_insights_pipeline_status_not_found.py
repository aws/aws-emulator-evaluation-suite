"""update-media-insights-pipeline-status-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-media-insights-pipeline-status-not-found"
GROUP = "errors"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMediaInsightsPipelineStatus on a nonexistent Identifier fails with NotFoundException
    "Unable to find the requested identifier"; as a control, an update of a real media insights
    pipeline configuration's role by ARN succeeds and an independent Get returns the new role."""
    chime = ctx.client("chime-sdk-media-pipelines")

    bogus_identifier = "00000000-0000-0000-0000-000000000000"
    error = _client_error(
        lambda: chime.update_media_insights_pipeline_status(
            Identifier=bogus_identifier, UpdateStatus="Pause"
        )
    )
    assert error["Code"] == "NotFoundException", f"actual error: {error!r}"
    assert error["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message: {error['Message']!r}"
    )

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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )["MediaInsightsPipelineConfiguration"]
    config_arn = created["MediaInsightsPipelineConfigurationArn"]
    ctx.on_cleanup(lambda: chime.delete_media_insights_pipeline_configuration(Identifier=config_arn))

    # Positive control: an update by identifier on a real resource succeeds. Identifier takes the
    # configuration's name or ARN; AWS answers its MediaInsightsPipelineConfigurationId with
    # NotFoundException.
    updated = _update_config_with_retry(
        ctx,
        chime,
        Identifier=config_arn,
        ResourceAccessRoleArn=other_role_arn,
        Elements=_transcribe_elements("en-US") + [sink_element],
    )["MediaInsightsPipelineConfiguration"]
    assert updated["ResourceAccessRoleArn"] == other_role_arn, (
        f"positive control: update-by-id on a real config did not take effect: {updated}"
    )

    # terminal read is independent of the mutating Update call, at the destination
    fetched = _get_config_tolerant(chime, config_arn)
    assert fetched["ResourceAccessRoleArn"] == other_role_arn, (
        f"positive control: independent Get did not reflect the update: {fetched}"
    )


def _create_kinesis_sink_element(ctx) -> dict:
    """CreateMediaInsightsPipelineConfiguration requires at least one sink element for a
    transcribe processor; real-time transcription insights require a KinesisDataStreamSink
    (per AWS docs, "Combining transcription with recording sinks")."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-micfg-sink-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
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
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
    (not a bare sleep) until the new role is recognized or the timeout expires."""
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
    """A configuration just updated may not be immediately visible to Get (eventual
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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a
    target that accepts what AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
