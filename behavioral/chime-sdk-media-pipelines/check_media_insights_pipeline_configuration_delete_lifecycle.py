"""media-insights-pipeline-configuration-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "media-insights-pipeline-configuration-delete-lifecycle"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMediaInsightsPipelineConfiguration removes the configuration: a subsequent Get
    returns NotFoundException and it disappears from the List results."""
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["MediaInsightsPipelineConfiguration"]
    config_arn = created["MediaInsightsPipelineConfigurationArn"]

    _delete_config_tolerant(chime, config_arn)

    error = _client_error(lambda: chime.get_media_insights_pipeline_configuration(Identifier=config_arn))
    assert error["Code"] == "NotFoundException", f"expected NotFoundException on Get after delete, got {error!r}"
    assert error["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message on Get after delete: {error['Message']!r}"
    )

    names_in_list = {
        item["MediaInsightsPipelineConfigurationName"]
        for item in _list_all_configs(chime)
    }
    assert name not in names_in_list, (
        f"deleted config {name!r} still present in ListMediaInsightsPipelineConfigurations: "
        f"{names_in_list!r}"
    )

    second_delete = _client_error(lambda: chime.delete_media_insights_pipeline_configuration(Identifier=config_arn))
    assert second_delete["Code"] == "NotFoundException", (
        f"expected NotFoundException on double-delete of already-deleted config, got {second_delete!r}"
    )
    assert second_delete["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message on double-delete: {second_delete['Message']!r}"
    )


def _create_kinesis_sink_element(ctx) -> dict:
    """CreateMediaInsightsPipelineConfiguration requires at least one sink element for a
    transcribe processor; real-time transcription insights require a KinesisDataStreamSink
    (per AWS docs, "Combining transcription with recording sinks")."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-micfg-sink-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real-check": CHECK})
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


def _delete_config_tolerant(chime, config_arn: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> None:
    """A configuration just created may not be immediately visible/consistent for Delete
    (eventual consistency); retry through a short window of NotFoundException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            chime.delete_media_insights_pipeline_configuration(Identifier=config_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


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
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

