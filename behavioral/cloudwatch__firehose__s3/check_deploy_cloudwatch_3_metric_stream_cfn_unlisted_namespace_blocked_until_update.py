"""deploy-cloudwatch-3-metric-stream-cfn-unlisted-namespace-blocked-until-update."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-3-metric-stream-cfn-unlisted-namespace-blocked-until-update"
GROUP = "deploy-metric-stream"
SERVICES = ["cloudwatch", "firehose", "s3"]

_METRIC_NAME = "DeployFilteredMetric"
_VALUE_LISTED = 111.0
_VALUE_UNLISTED = 222.0
_UNIT = "Count"
_PREFIX = "sim2real-metric-stream/"
# Ceilings, not waits: every one of them ends as soon as its condition is observed.
_STACK_TIMEOUT_S = 600.0
_DELIVERY_TIMEOUT_S = 480.0


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
                        # 60 s is the smallest interval Firehose accepts; larger only delays the
                        # delivery this check waits for.
                        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
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


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:negative-delivery",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """A namespace absent from the CFN-declared IncludeFilters never reaches S3 while a listed one
    does; after an UpdateStack that adds it, the same stream delivers it to the same bucket.
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    s3 = ctx.client("s3")

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
    ms = cw.get_metric_stream(Name=stream)
    assert ms["State"] == "running", f"metric stream {stream!r} is {ms['State']!r}, not 'running'"
    before = [f["Namespace"] for f in ms.get("IncludeFilters", [])]
    assert before == [listed], f"IncludeFilters namespaces are {before!r}, expected {[listed]!r}"

    def publish_both() -> None:
        _publish(cw, listed, _VALUE_LISTED)
        _publish(cw, unlisted, _VALUE_UNLISTED)

    publish_both()
    # Barrier: the listed namespace must arrive in >= 2 distinct objects (one arrival can be luck),
    # with both namespaces published in the same minutes, before the unlisted one is ruled absent.
    bodies, records = _poll_until(
        lambda: _records(s3, bucket),
        lambda got: len(_keys_with(got, listed)) >= 2,
        timeout_s=_DELIVERY_TIMEOUT_S, interval_s=15.0,
        description=f"the listed namespace {listed!r} delivered in two objects to s3://{bucket}",
        between=publish_both,
    )
    mine = [r for r in records if r.get("namespace") == listed]
    assert all(r["value"]["max"] == _VALUE_LISTED for r in mine), (
        f"the listed namespace exported values {[r['value'] for r in mine]!r}, expected max "
        f"{_VALUE_LISTED!r}"
    )
    leaked = [r for r in records if r.get("namespace") == unlisted]
    assert leaked == [], (
        f"IncludeFilters lists only {listed!r}, yet {len(leaked)} record(s) of the unlisted "
        f"namespace {unlisted!r} were delivered while it was being published: {leaked[:2]!r}"
    )
    seen = sorted({r.get("namespace") for r in records}, key=str)
    assert seen == [listed], f"the bucket holds namespaces {seen!r}, expected only {[listed]!r}"

    # Close the loop: change ONLY the filter, and the same bucket must now receive.
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

    publish_both()
    _, records = _poll_until(
        lambda: _records(s3, bucket),
        lambda got: any(r.get("namespace") == unlisted for r in got[1]),
        timeout_s=_DELIVERY_TIMEOUT_S, interval_s=15.0,
        description=(f"the newly-listed namespace {unlisted!r} delivered to s3://{bucket} after "
                     f"the stack update, proving only the filter suppressed it"),
        between=publish_both,
    )
    repaired = [r for r in records if r.get("namespace") == unlisted]
    assert all(r["metric_name"] == _METRIC_NAME for r in repaired), (
        f"{sorted({r['metric_name'] for r in repaired})!r}"
    )
    assert all(r["value"]["max"] == _VALUE_UNLISTED for r in repaired), (
        f"the newly-listed namespace exported {[r['value'] for r in repaired]!r}, expected max "
        f"{_VALUE_UNLISTED!r} -- the payload is not the data published to it"
    )
    assert all(r["metric_stream_name"] == stream for r in repaired), (
        f"{sorted({r['metric_stream_name'] for r in repaired})!r} != {stream!r}"
    )


def _publish(cw, namespace: str, value: float) -> datetime:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": _METRIC_NAME, "Timestamp": now, "Value": value, "Unit": _UNIT}],
    )
    return now


def _keys_with(got, namespace: str) -> list[str]:
    """Keys of delivered objects holding at least one record of `namespace`."""
    bodies, _ = got
    return sorted(k for k, body in bodies.items()
                  if any(r.get("namespace") == namespace for r in _parse(body)))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str,
                between=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not met within {timeout_s}s; last {last!r}"[:3000])
        if between is not None:
            # A metric stream exports only what is being written, so keep the series alive.
            between()
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


def _records(s3, bucket: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Every delivered object body in the bucket, and every JSON record they hold."""
    bodies: dict[str, str] = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
            bodies[obj["Key"]] = raw.decode("utf-8")
    return bodies, [r for body in bodies.values() for r in _parse(body)]


def _parse(body: str) -> list[dict[str, Any]]:
    """Firehose concatenates the stream's JSON documents; some are newline-separated, some not."""
    decoder = json.JSONDecoder()
    out: list[dict[str, Any]] = []
    idx = 0
    while idx < len(body):
        while idx < len(body) and body[idx] in " \r\n\t":
            idx += 1
        if idx >= len(body):
            break
        obj, idx = decoder.raw_decode(body, idx)
        out.append(obj)
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
