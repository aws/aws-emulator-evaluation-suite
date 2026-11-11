"""deploy-cloudwatch-3-metric-stream-cfn-include-filter-update-echoed-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-3-metric-stream-cfn-include-filter-update-echoed-in-place"
GROUP = "deploy-metric-stream"
SERVICES = ["cloudformation", "cloudwatch", "firehose", "s3"]

_PREFIX = "sim2real-metric-stream/"
#: The template's S3 destination buffer: the 60 s interval and 1 MiB size it declares.
_BUFFERING = {"IntervalInSeconds": 60, "SizeInMBs": 1}
# A ceiling, not a wait: it ends as soon as the stack reaches a terminal status.
_STACK_TIMEOUT_S = 600.0


def _template(*, bucket: str, fh_name: str, fh_role: str, ms_role: str, stream: str,
              namespaces: list[str]) -> str:
    """Bucket -> Firehose (role) -> MetricStream (role), every resource name pinned."""
    trust = lambda svc: {  # noqa: E731
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": svc},
                       "Action": "sts:AssumeRole"}],
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
            "FirehoseRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": fh_role,
                    "AssumeRolePolicyDocument": trust("firehose.amazonaws.com"),
                    "Policies": [{
                        "PolicyName": "sim2real-firehose-to-s3",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation",
                                           "s3:GetObject", "s3:ListBucket",
                                           "s3:ListBucketMultipartUploads", "s3:PutObject"],
                                "Resource": [{"Fn::GetAtt": ["Bucket", "Arn"]},
                                             {"Fn::Sub": "${Bucket.Arn}/*"}],
                            }],
                        },
                    }],
                },
            },
            "DeliveryStream": {
                "Type": "AWS::KinesisFirehose::DeliveryStream",
                "Properties": {
                    "DeliveryStreamName": fh_name,
                    "DeliveryStreamType": "DirectPut",
                    "ExtendedS3DestinationConfiguration": {
                        "BucketARN": {"Fn::GetAtt": ["Bucket", "Arn"]},
                        "RoleARN": {"Fn::GetAtt": ["FirehoseRole", "Arn"]},
                        "Prefix": _PREFIX,
                        "ErrorOutputPrefix": "sim2real-errors/",
                        "BufferingHints": _BUFFERING,
                        "CompressionFormat": "UNCOMPRESSED",
                    },
                },
            },
            "MetricStreamRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": ms_role,
                    "AssumeRolePolicyDocument": trust("streams.metrics.cloudwatch.amazonaws.com"),
                    "Policies": [{
                        "PolicyName": "sim2real-stream-to-firehose",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                                "Resource": {"Fn::GetAtt": ["DeliveryStream", "Arn"]},
                            }],
                        },
                    }],
                },
            },
            "MetricStream": {
                "Type": "AWS::CloudWatch::MetricStream",
                "Properties": {
                    "Name": stream,
                    "FirehoseArn": {"Fn::GetAtt": ["DeliveryStream", "Arn"]},
                    "RoleArn": {"Fn::GetAtt": ["MetricStreamRole", "Arn"]},
                    "OutputFormat": "json",
                    "IncludeFilters": [{"Namespace": ns} for ns in namespaces],
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "DeliveryStreamArn": {"Value": {"Fn::GetAtt": ["DeliveryStream", "Arn"]}},
            "MetricStreamName": {"Value": {"Ref": "MetricStream"}},
            "MetricStreamRoleArn": {"Value": {"Fn::GetAtt": ["MetricStreamRole", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """The CFN-declared metric stream and delivery stream echo their IncludeFilters, output format,
    Firehose target and buffering hints; an UpdateStack that adds a namespace updates it in place.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStream.html
    Reference: https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    stack_name = ctx.unique_name("sim2real-xsvc-msf-")
    bucket = ctx.unique_name("sim2real-xsvc-msfb-")
    names = dict(bucket=bucket, fh_name=ctx.unique_name("sim2real-xsvc-msffh-"),
                 fh_role=ctx.unique_name("sim2real-xsvc-msffhrole-"),
                 ms_role=ctx.unique_name("sim2real-xsvc-msfrole-"),
                 stream=ctx.unique_name("sim2real-xsvc-msfstream-"))
    stream = names["stream"]
    listed = "Sim2Real/DeployMetricStream/" + ctx.unique_name("listed")
    unlisted = "Sim2Real/DeployMetricStream/" + ctx.unique_name("unlisted")

    # Firehose-written objects are not stack-owned and a non-empty bucket blocks stack deletion.
    ctx.on_cleanup(lambda: _teardown_net(cfn, s3, stack_name, bucket))
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(namespaces=[listed], **names),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": "deploy-metric-stream"}],
    )["StackId"]
    status = _poll_until(lambda: _stack_status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                         timeout_s=_STACK_TIMEOUT_S, interval_s=5.0,
                         description=f"stack {stack_name} reaching a terminal create status")
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_name!r} ended {status!r}; failed resources: {_failures(cfn, stack_id)!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])}

    ms = cw.get_metric_stream(Name=stream)
    got = (ms["Name"], ms["State"], ms["OutputFormat"], ms["FirehoseArn"], ms["RoleArn"])
    want = (stream, "running", "json", outputs["DeliveryStreamArn"], outputs["MetricStreamRoleArn"])
    assert got == want, f"metric stream {stream!r} reports {got!r}, expected {want!r}"
    before = [f["Namespace"] for f in ms.get("IncludeFilters", [])]
    assert before == [listed], f"IncludeFilters namespaces are {before!r}, expected {[listed]!r}"
    assert ms.get("ExcludeFilters", []) == [], f"ExcludeFilters are {ms.get('ExcludeFilters')!r}"

    delivery = firehose.describe_delivery_stream(DeliveryStreamName=names["fh_name"])[
        "DeliveryStreamDescription"]
    assert delivery["DeliveryStreamARN"] == outputs["DeliveryStreamArn"], (
        f"{delivery['DeliveryStreamARN']!r} != {outputs['DeliveryStreamArn']!r}"
    )
    destination = delivery["Destinations"][0]["ExtendedS3DestinationDescription"]
    got = (destination["BucketARN"], destination["Prefix"], destination["BufferingHints"])
    want = (f"arn:aws:s3:::{bucket}", _PREFIX, _BUFFERING)
    assert got == want, f"the delivery stream's S3 destination is {got!r}, expected {want!r}"

    # Change ONLY the filter: the stream must be updated, not replaced.
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(namespaces=[listed, unlisted], **names),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": "deploy-metric-stream"}],
    )
    status = _poll_until(lambda: _stack_status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                         timeout_s=_STACK_TIMEOUT_S, interval_s=5.0,
                         description=f"stack {stack_name} reaching a terminal update status")
    assert status == "UPDATE_COMPLETE", (
        f"updating only IncludeFilters ended {status!r}; failed resources: "
        f"{_failures(cfn, stack_id)!r}"
    )
    after = cw.get_metric_stream(Name=stream)
    assert sorted(f["Namespace"] for f in after.get("IncludeFilters", [])) == sorted([listed, unlisted]), (
        f"after the update IncludeFilters are {after.get('IncludeFilters')!r}"
    )
    assert after["State"] == "running", f"after the update the stream is {after['State']!r}"
    assert after["Arn"] == ms["Arn"], (
        f"a filter-only update replaced the stream: {ms['Arn']!r} -> {after['Arn']!r}"
    )
    assert after["FirehoseArn"] == ms["FirehoseArn"], (
        f"a filter-only update moved the stream's target: {ms['FirehoseArn']!r} -> "
        f"{after['FirehoseArn']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not met within {timeout_s}s; last {last!r}"[:3000])
        time.sleep(interval_s)


def _stack_status(cfn, stack: str) -> str:
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return "GONE"
        raise


def _failures(cfn, stack: str) -> list[tuple[str, str, str]]:
    try:
        events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    except ClientError as exc:
        return [("<describe_stack_events>", exc.response["Error"]["Code"], "")]
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason", ""))
            for e in events if e["ResourceStatus"].endswith("_FAILED")][:6]


def _empty_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _drain_and_delete(cfn, s3, stack: str, bucket: str, *, rounds: int = 3) -> tuple[str, int]:
    """Empty the bucket, delete the stack, and repeat only if a late Firehose flush refilled it."""
    status = _stack_status(cfn, stack)
    for i in range(1, rounds + 1):
        _empty_bucket(s3, bucket)
        cfn.delete_stack(StackName=stack)
        status = _poll_until(lambda: _stack_status(cfn, stack),
                             lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
                             timeout_s=_STACK_TIMEOUT_S, interval_s=5.0,
                             description=f"stack {stack} reaching a terminal delete status")
        if status != "DELETE_FAILED":
            return status, i
    return status, rounds


def _teardown_net(cfn, s3, stack: str, bucket: str) -> None:
    """Drain the bucket and delete the stack; any failure other than not-found raises."""
    try:
        status, rounds = _drain_and_delete(cfn, s3, stack, bucket)
        if status not in {"DELETE_COMPLETE", "GONE"}:
            raise RuntimeError(f"stack {stack} ended {status} after {rounds} rounds; bucket {bucket} "
                               f"and the stack's roles/streams may be stranded")
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            teardown_code not in ("NoSuchBucket",)
            and not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"stack {stack} teardown failed: {type(exc).__name__}: {exc}"
            ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
