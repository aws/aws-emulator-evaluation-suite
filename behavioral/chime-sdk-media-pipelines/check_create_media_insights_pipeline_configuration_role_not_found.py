"""create-media-insights-pipeline-configuration-role-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-media-insights-pipeline-configuration-role-not-found"
GROUP = "errors"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMediaInsightsPipelineConfiguration with a nonexistent ResourceAccessRoleArn fails with
    ForbiddenException "Service does not have permission to invoke role: <arn>" and creates no
    configuration; the same request naming a real role succeeds and keeps its name."""
    chime = ctx.client("chime-sdk-media-pipelines")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_iam_role_for_media_insights(ctx)
    elements = [_transcribe_element("en-US"), _create_kinesis_sink_element(ctx)]

    valid_name = ctx.unique_name("sim2real-micfg-")
    control = _create_config_with_retry(
        ctx,
        chime,
        MediaInsightsPipelineConfigurationName=valid_name,
        ResourceAccessRoleArn=role_arn,
        Elements=elements,
    )["MediaInsightsPipelineConfiguration"]
    control_arn = control["MediaInsightsPipelineConfigurationArn"]
    ctx.on_cleanup(
        lambda: chime.delete_media_insights_pipeline_configuration(Identifier=control_arn)
    )
    assert control["MediaInsightsPipelineConfigurationName"] == valid_name, (
        f"positive control did not persist the requested name: {control}"
    )

    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-no-such-role-')}"
    name = ctx.unique_name("sim2real-micfg-")
    error = _client_error(
        lambda: chime.create_media_insights_pipeline_configuration(
            MediaInsightsPipelineConfigurationName=name,
            ResourceAccessRoleArn=bogus_role_arn,
            Elements=elements,
        )
    )
    assert error["Code"] == "ForbiddenException", f"actual error: {error!r}"
    expected_message = f"Service does not have permission to invoke role: {bogus_role_arn}"
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )

    matches = [
        item
        for item in _list_all_configs(chime)
        if item["MediaInsightsPipelineConfigurationName"] == name
    ]
    assert matches == [], f"configuration should not have been created: {matches}"


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


def _transcribe_element(language_code: str) -> dict:
    return {
        "Type": "AmazonTranscribeProcessor",
        "AmazonTranscribeProcessorConfiguration": {"LanguageCode": language_code},
    }


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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target
    that accepts what AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS accepted the bogus-role create instead of rejecting it: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
