"""deploy-cloudwatch-3-metric-stream-cfn-delivers-put-metric-to-s3."""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-3-metric-stream-cfn-delivers-put-metric-to-s3"
GROUP = "deploy-metric-stream"
SERVICES = ["cloudwatch", "firehose", "s3"]

_METRIC_NAME = "DeployStreamedMetric"
_VALUE = 4242.0
_UNIT = "Count"
_PREFIX = "sim2real-metric-stream/"
# Ceilings, not waits: every one of them ends as soon as its condition is observed.
_STACK_TIMEOUT_S = 600.0
_DELIVERY_TIMEOUT_S = 600.0
_GONE_TIMEOUT_S = 180.0


def _template(*, bucket: str, fh_name: str, fh_role: str, ms_role: str, stream: str,
              namespace: str) -> str:
    """Bucket -> Firehose (role) -> MetricStream (role), every name pinned for cleanup."""
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
                    "IncludeFilters": [{"Namespace": namespace}],
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
    "axis:happy-path",
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
    """A CloudFormation-deployed metric stream exports a published datapoint (name, exact value,
    stream, account, region, only the filtered namespace) to S3; deleting the stack removes it all.
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    stack_name = ctx.unique_name("sim2real-xsvc-ms-")
    bucket = ctx.unique_name("sim2real-xsvc-msb-")
    fh_name = ctx.unique_name("sim2real-xsvc-msfh-")
    fh_role = ctx.unique_name("sim2real-xsvc-msfhrole-")
    ms_role = ctx.unique_name("sim2real-xsvc-msrole-")
    stream = ctx.unique_name("sim2real-xsvc-mstream-")
    namespace = "Sim2Real/DeployMetricStream/" + ctx.unique_name("ns")

    # The net first: it drains the bucket the stack cannot delete while it holds objects.
    ctx.on_cleanup(lambda: _teardown_net(cfn, s3, stack_name, bucket))
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(bucket=bucket, fh_name=fh_name, fh_role=fh_role, ms_role=ms_role,
                               stream=stream, namespace=namespace),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": "deploy-metric-stream"}],
    )["StackId"]
    status = _poll_until(lambda: _stack_status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                         timeout_s=_STACK_TIMEOUT_S, interval_s=5.0,
                         description=f"stack {stack_name} reaching a terminal create status")
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_name!r} ended {status!r}; failed resources: {_failures(cfn, stack_id)!r}"
    )

    outputs = _outputs(cfn, stack_id)
    assert outputs.get("BucketName") == bucket, f"stack outputs {outputs!r} name the wrong bucket"
    assert outputs.get("MetricStreamName") == stream, (
        f"Ref on the MetricStream must be its name {stream!r}; outputs were {outputs!r}"
    )
    fh_arn = outputs["DeliveryStreamArn"]

    desc = firehose.describe_delivery_stream(DeliveryStreamName=fh_name)["DeliveryStreamDescription"]
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"the stack completed but delivery stream {fh_name!r} is {desc['DeliveryStreamStatus']!r}"
    )
    assert desc["DeliveryStreamARN"] == fh_arn, f"{desc['DeliveryStreamARN']!r} vs {fh_arn!r}"
    dest = desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert dest["BucketARN"] == f"arn:aws:s3:::{bucket}", (
        f"the delivery stream writes to {dest['BucketARN']!r}, not the stack's bucket {bucket!r}"
    )

    ms = cw.get_metric_stream(Name=stream)
    assert ms["State"] == "running", f"metric stream {stream!r} is {ms['State']!r}, not 'running'"
    assert ms["OutputFormat"] == "json", f"OutputFormat is {ms['OutputFormat']!r}, expected 'json'"
    assert ms["FirehoseArn"] == fh_arn, f"stream targets {ms['FirehoseArn']!r}, expected {fh_arn!r}"
    assert ms["RoleArn"] == outputs["MetricStreamRoleArn"], (
        f"stream assumes {ms['RoleArn']!r}, expected {outputs['MetricStreamRoleArn']!r}"
    )
    included = [f["Namespace"] for f in ms.get("IncludeFilters", [])]
    assert included == [namespace], f"IncludeFilters namespaces are {included!r}, expected {[namespace]!r}"
    assert not ms.get("ExcludeFilters"), f"ExcludeFilters unexpectedly set: {ms.get('ExcludeFilters')!r}"

    # ---- the data plane: a published datapoint has to come out of the far end ----
    published_at = _publish(cw, namespace)
    found = _poll_until(
        lambda: _records(s3, bucket),
        lambda got: any(r.get("namespace") == namespace and r.get("metric_name") == _METRIC_NAME
                        for r in got[1]),
        timeout_s=_DELIVERY_TIMEOUT_S, interval_s=15.0,
        description=f"a record for {namespace}/{_METRIC_NAME} delivered to s3://{bucket}/{_PREFIX}",
        between=lambda: _publish(cw, namespace),
    )
    bodies, records = found
    assert any(_METRIC_NAME in body for body in bodies.values()), (
        f"no delivered object body contains the metric name {_METRIC_NAME!r}: keys {sorted(bodies)!r}"
    )
    assert all(key.startswith(_PREFIX) for key in bodies), (
        f"Firehose wrote outside the configured prefix {_PREFIX!r}: {sorted(bodies)!r}"
    )
    rec = next(r for r in records
               if r.get("namespace") == namespace and r.get("metric_name") == _METRIC_NAME)
    assert rec["value"]["max"] == _VALUE and rec["value"]["min"] == _VALUE, (
        f"the exported value is {rec['value']!r}; PutMetricData sent {_VALUE!r} every time"
    )
    assert rec["value"]["count"] >= 1 and rec["value"]["sum"] == _VALUE * rec["value"]["count"], (
        f"the exported statistics are inconsistent with {rec['value']['count']!r} samples of "
        f"{_VALUE!r}: {rec['value']!r}"
    )
    assert rec["unit"] == _UNIT, f"the exported unit is {rec['unit']!r}, expected {_UNIT!r}"
    assert rec["metric_stream_name"] == stream, (
        f"the record names stream {rec['metric_stream_name']!r}, expected {stream!r}"
    )
    assert rec["account_id"] == account_id, f"record account {rec['account_id']!r} != {account_id!r}"
    assert rec["region"] == ctx.region, f"record region {rec['region']!r} != {ctx.region!r}"
    assert rec["timestamp"] >= int(published_at.timestamp() * 1000) - 300_000, (
        f"the exported timestamp {rec['timestamp']!r} predates the first publish at "
        f"{published_at.isoformat()}"
    )
    stray = sorted({r.get("namespace") for r in records} - {namespace}, key=str)
    assert not stray, (
        f"IncludeFilters names only {namespace!r}, yet the bucket received namespaces {stray!r}"
    )

    # ---- teardown is part of the claim: the stack takes the pipeline with it ----
    # CloudFormation cannot delete a non-empty bucket, and a late Firehose flush can refill it.
    final, rounds = _drain_and_delete(cfn, s3, stack_id, bucket)
    assert final == "DELETE_COMPLETE", (
        f"stack {stack_name!r} ended {final!r} after {rounds} drain+delete round(s); "
        f"failed resources: {_failures(cfn, stack_id)!r}"
    )
    names = _list_metric_stream_names(cw)
    assert stream not in names, f"metric stream {stream!r} survived its stack's deletion"
    err = _error(lambda: cw.get_metric_stream(Name=stream))
    expected = ("ResourceNotFoundException", "")  # AWS sends this one with no message
    assert err == expected, (
        f"GetMetricStream on the deleted stream returned {err!r}, expected {expected!r}"
    )
    fh_err = _poll_until(
        lambda: _error_or_status(
            lambda: firehose.describe_delivery_stream(DeliveryStreamName=fh_name)
            ["DeliveryStreamDescription"]["DeliveryStreamStatus"]),
        lambda c: isinstance(c, tuple),
        timeout_s=_GONE_TIMEOUT_S, interval_s=5.0,
        description=f"delivery stream {fh_name!r} disappearing after its stack was deleted",
    )
    expected = (
        "ResourceNotFoundException",
        # AWS leaves the stream name out of this message once the stream is gone.
        f"Firehose under account {account_id} not found.",
    )
    assert fh_err == expected, f"DescribeDeliveryStream returned {fh_err!r}, expected {expected!r}"
    s3_err = _error(lambda: s3.list_objects_v2(Bucket=bucket, MaxKeys=1))
    expected = ("NoSuchBucket", "The specified bucket does not exist")
    assert s3_err == expected, (
        f"the stack's bucket {bucket!r} answers ListObjectsV2 with {s3_err!r} after DELETE_COMPLETE, "
        f"expected {expected!r}"
    )


def _publish(cw, namespace: str) -> datetime:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": _METRIC_NAME, "Timestamp": now, "Value": _VALUE, "Unit": _UNIT}],
    )
    return now


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


def _outputs(cfn, stack: str) -> dict[str, str]:
    st = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in st.get("Outputs", [])}


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
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
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
    """Teardown that raises on failure rather than leaving the stack behind."""
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
    """Every delivered object body under the prefix, and every JSON record they hold."""
    bodies: dict[str, str] = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if raw[:2] == b"\x1f\x8b":
                raw = gzip.decompress(raw)
            bodies[obj["Key"]] = raw.decode("utf-8")
    records: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    for body in bodies.values():
        # Firehose concatenates the stream's JSON documents; some are newline-separated, some not.
        idx = 0
        while idx < len(body):
            while idx < len(body) and body[idx] in " \r\n\t":
                idx += 1
            if idx >= len(body):
                break
            obj, idx = decoder.raw_decode(body, idx)
            records.append(obj)
    return bodies, records


def _list_metric_stream_names(cw) -> list[str]:
    names: list[str] = []
    kwargs: dict[str, Any] = {}
    while True:
        page = cw.list_metric_streams(**kwargs)
        names.extend(e["Name"] for e in page.get("Entries", []))
        if not page.get("NextToken"):
            return names
        kwargs["NextToken"] = page["NextToken"]


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises. A call that SUCCEEDS is a failure in its own
    right."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to fail but succeeded: {result!r}"[:2000])


def _error_or_status(fn):
    """(code, message) of fn()'s error, or the string fn() returned while the resource still exists
    (polling a delete)."""
    try:
        return f"exists:{fn()}"
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
