"""cloudwatch-log-processing-stream-rejects-direct-put-record-from-non-cloudwatch-source."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudwatch-log-processing-stream-rejects-direct-put-record-from-non-cloudwatch-source"
GROUP = "data-plane"
SERVICES = ["firehose", "logs", "s3"]

# CloudWatch Logs' hop to a brand-new Firehose destination plus the 60 s buffer flush varies
# from about 90 s to beyond 210 s on AWS, so the delivery wait allows 360 s.
_DELIVERY_BUDGET_S = 360.0
_POLL_INTERVAL_S = 2.0
_EVENT_COUNT = 12
_GZIP_MAGIC = b"\x1f\x8b"

# A direct PutRecord into a stream whose ProcessingConfiguration declares CloudWatchLogProcessing
# raises InvalidSourceException.
_EXPECTED_CODE = "InvalidSourceException"


def _paged_keys(s3, bucket: str, prefix: str) -> list[str]:
    """Every key under prefix, across all pages."""
    out: list[str] = []
    token = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        out.extend(o["Key"] for o in resp.get("Contents", []))
        if not resp.get("IsTruncated"):
            return sorted(out)
        token = resp["NextContinuationToken"]


def _concat_objects(s3, bucket: str, keys: list[str]) -> bytes:
    return b"".join(s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in keys)


def _error_code(fn):
    """The error code a call raised. Raises when the call unexpectedly SUCCEEDS, because that is
    the strongest signal available and a falsy sentinel would disguise it as a name mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(
        f"the call was expected to be rejected with {_EXPECTED_CODE} and instead SUCCEEDED, "
        f"returning {result!r}"
    )


def _create_delivery_stream(ctx, name: str, config: dict) -> str:
    """Firehose validates the delivery role by assuming it, so CreateDeliveryStream transiently
    reports InvalidArgumentException while a freshly created role propagates."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            return fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real", "Value": "f4-cwlproc-source-gate"}],
            )["DeliveryStreamARN"]
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"CreateDeliveryStream({name}) never succeeded: {last}")


# Inside the 900 s firehose cleanup budget, one deadline shared by every stream teardown of a run.
_TEARDOWN_S = 780.0


def _delete_stream(firehose, name, shared):
    """Delete the stream and wait every 2 s until DescribeDeliveryStream answers not-found.
    DeleteDeliveryStream refuses a stream still CREATING with ResourceInUseException, which is retried;
    any other failure, or the shared deadline passing, raises."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_S)
    deleted = False
    while True:
        try:
            if not deleted:
                firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present at the teardown deadline")
        time.sleep(2)


def _await_active(ctx, name: str) -> dict:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 180.0
    status = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        time.sleep(4.0)
    raise AssertionError(f"delivery stream {name!r} never became ACTIVE (last status {status!r})")


def _put_subscription_filter(ctx, group: str, filter_name: str, arn: str, role_arn: str) -> None:
    """PutSubscriptionFilter delivers a synthetic test message before accepting the filter, so
    it transiently reports InvalidParameterException while the role propagates."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=group, filterName=filter_name, filterPattern="",
                destinationArn=arn, roleArn=role_arn,
            )
            return
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(4.0)
    raise AssertionError(f"PutSubscriptionFilter({filter_name}) never succeeded: {last}")


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stream declaring CloudWatchLogProcessing refuses a direct PutRecord of a CloudWatch Logs
    envelope with InvalidSourceException and never delivers it, while it delivers subscription-filter
    events and an unprocessed twin accepts and delivers the identical bytes."""
    logs = ctx.client("logs")
    fh = ctx.client("firehose")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-f4sg-")
    fh_role = ctx.unique_name("sim2real-behav-f4sgfh-")
    logs_role = ctx.unique_name("sim2real-behav-f4sglg-")
    group = ctx.unique_name("sim2real-behav-f4sglgrp-")
    stream = ctx.unique_name("sim2real-behav-f4sgls-")
    gated = ctx.unique_name("sim2real-behav-f4sgg-")
    open_stream = ctx.unique_name("sim2real-behav-f4sgo-")
    gated_filter = ctx.unique_name("sim2real-f4sggf-")
    open_filter = ctx.unique_name("sim2real-f4sgof-")

    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )

    def _empty_and_delete_bucket(_b=bucket):
        # 40 s: all of a check's cleanups share a 60 s budget, and this one is registered first so it runs last.
        deadline = time.monotonic() + 40.0
        while time.monotonic() < deadline:
            token = None
            pending = False
            while True:
                kwargs = {"Bucket": _b}
                if token:
                    kwargs["ContinuationToken"] = token
                resp = s3.list_objects_v2(**kwargs)
                keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
                if keys:
                    pending = True
                    s3.delete_objects(Bucket=_b, Delete={"Objects": keys})
                if not resp.get("IsTruncated"):
                    break
                token = resp["NextContinuationToken"]
            try:
                s3.delete_bucket(Bucket=_b)
                return
            except ClientError as err:
                if err.response["Error"]["Code"] != "BucketNotEmpty" and not pending:
                    raise
                time.sleep(5.0)
        raise AssertionError(f"bucket {_b!r} could not be emptied and deleted")

    ctx.on_cleanup(_empty_and_delete_bucket)

    fh_role_arn = iam.create_role(
        RoleName=fh_role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "firehose.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav firehose->s3 delivery role",
        Tags=[{"Key": "sim2real", "Value": "f4-cwlproc-source-gate"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role))
    iam.put_role_policy(
        RoleName=fh_role, PolicyName="s3-write",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation",
                                      "s3:GetObject", "s3:ListBucket",
                                      "s3:ListBucketMultipartUploads", "s3:PutObject"],
                           "Resource": [f"arn:aws:s3:::{bucket}",
                                        f"arn:aws:s3:::{bucket}/*"]}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role, PolicyName="s3-write"))

    def _dest(prefix: str, processing: dict) -> dict:
        return {
            "RoleARN": fh_role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "Prefix": prefix + "/",
            "ErrorOutputPrefix": prefix + "-err/",
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
            "CompressionFormat": "UNCOMPRESSED",
            "ProcessingConfiguration": processing,
        }

    gated_arn = _create_delivery_stream(ctx, gated, _dest(gated, {
        "Enabled": True,
        "Processors": [
            {"Type": "Decompression",
             "Parameters": [{"ParameterName": "CompressionFormat", "ParameterValue": "GZIP"}]},
            {"Type": "CloudWatchLogProcessing",
             "Parameters": [{"ParameterName": "DataMessageExtraction",
                             "ParameterValue": "true"}]},
            {"Type": "AppendDelimiterToRecord", "Parameters": []},
        ],
    }))
    stream_teardown = {}
    ctx.on_cleanup(lambda: _delete_stream(fh, gated, stream_teardown))
    open_arn = _create_delivery_stream(ctx, open_stream, _dest(open_stream, {"Enabled": False}))
    ctx.on_cleanup(lambda: _delete_stream(fh, open_stream, stream_teardown))

    gated_desc = _await_active(ctx, gated)
    open_desc = _await_active(ctx, open_stream)

    logs_role_arn = iam.create_role(
        RoleName=logs_role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "logs.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav logs->firehose subscription role",
        Tags=[{"Key": "sim2real", "Value": "f4-cwlproc-source-gate"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=logs_role))
    iam.put_role_policy(
        RoleName=logs_role, PolicyName="firehose-write",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                           "Resource": [gated_arn, open_arn]}],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=logs_role, PolicyName="firehose-write")
    )

    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    _put_subscription_filter(ctx, group, gated_filter, gated_arn, logs_role_arn)
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=gated_filter)
    )
    _put_subscription_filter(ctx, group, open_filter, open_arn, logs_role_arn)
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=open_filter)
    )

    # --- The one broken thing: the SOURCE. Byte-identical payload, both streams.
    direct_marker = ctx.unique_name("sim2real-f4-directput-")
    envelope = {
        "messageType": "DATA_MESSAGE",
        "owner": account,
        "logGroup": group,
        "logStream": stream,
        "subscriptionFilters": [gated_filter],
        "logEvents": [{"id": "0" * 56, "timestamp": int(time.time() * 1000),
                       "message": direct_marker}],
    }
    payload = gzip.compress(json.dumps(envelope).encode("utf-8"))

    code, message = _error_code(
        lambda: fh.put_record(DeliveryStreamName=gated, Record={"Data": payload})
    )
    assert code == _EXPECTED_CODE, (
        f"a direct firehose:PutRecord into the CloudWatchLogProcessing stream {gated!r} was "
        f"rejected with {code!r}, expected exactly {_EXPECTED_CODE!r}. Message was {message!r}"
    )
    expected = (
        f"Put to Firehose failed for AccountId: {account}, FirehoseName: {gated} "
        "because the request is not originating from CloudWatch."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # --- Positive control: the identical bytes into the stream that differs only by having no
    # CloudWatchLogProcessing processor.
    accepted = fh.put_record(DeliveryStreamName=open_stream, Record={"Data": payload})
    assert accepted["RecordId"], (
        f"the unprocessed stream {open_stream!r} returned no RecordId for the identical "
        f"payload: {accepted!r}. If both streams refuse a direct put, the rejection above is "
        f"not about CloudWatchLogProcessing"
    )

    # --- Prove the refusing stream is alive: a real subscription filter delivers into it.
    base_ms = int(time.time() * 1000)
    messages = [f"{group}-payload-{i:02d}" for i in range(_EVENT_COUNT)]
    logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": base_ms + i, "message": m} for i, m in enumerate(messages)],
    )

    # Poll until both payloads are present, not until any object exists: CloudWatch Logs first sends a
    # CONTROL_MESSAGE health check that Firehose can flush alone, well before the twelve events arrive.
    left = ctx.time_left()
    budget = _DELIVERY_BUDGET_S if left is None else max(1.0, min(_DELIVERY_BUDGET_S, left - 5.0))
    t0 = time.monotonic()
    gated_keys: list[str] = []
    open_keys: list[str] = []
    gated_body = b""
    open_body = b""
    open_text = ""
    while time.monotonic() - t0 < budget:
        gated_keys = _paged_keys(s3, bucket, gated + "/")
        open_keys = _paged_keys(s3, bucket, open_stream + "/")
        gated_body = _concat_objects(s3, bucket, gated_keys) if gated_keys else b""
        open_body = _concat_objects(s3, bucket, open_keys) if open_keys else b""
        open_text = ""
        if open_body[:2] == _GZIP_MAGIC:
            try:
                open_text = gzip.decompress(open_body).decode("utf-8")
            except (OSError, EOFError, UnicodeDecodeError):
                open_text = ""
        gated_probe = gated_body.decode("utf-8", "replace")
        if (all(m in gated_probe for m in messages)
                and direct_marker in open_text
                and all(m in open_text for m in messages)):
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert gated_keys and open_keys, (
        f"DATAPLANE_UNIMPLEMENTED: no delivery in {waited:.0f}s. The CloudWatchLogProcessing "
        f"stream's prefix holds {len(gated_keys)} objects and the unprocessed stream's holds "
        f"{len(open_keys)}. Without delivery the absence "
        f"asserted below would be unreadable -- it could be lag rather than the rejection"
    )

    gated_text = gated_body.decode("utf-8")

    # The refusing stream really is delivering: all twelve subscription-filter events arrived,
    # decompressed and unwrapped by AWS.
    assert gated_body[:2] != _GZIP_MAGIC, (
        f"the CloudWatchLogProcessing stream's object starts with the gzip magic "
        f"{gated_body[:2]!r}; Decompression did not run and the object below cannot be read as "
        f"extracted messages"
    )
    gated_lines = [ln for ln in gated_text.split("\n") if ln]
    assert gated_lines == messages, (
        f"the CloudWatchLogProcessing stream's non-empty lines are {gated_lines!r}; expected "
        f"exactly the {_EVENT_COUNT} subscription-filter messages {messages!r} -- this is what "
        f"proves the stream is functional and the absence below is the rejection"
    )

    # --- Effect absent: the refused record was never stored, anywhere under that stream.
    assert direct_marker not in gated_text, (
        f"the payload the CloudWatchLogProcessing stream REFUSED with {_EXPECTED_CODE} was "
        f"delivered to S3 anyway: marker {direct_marker!r} appears in its object. A target that "
        f"raises the error and stores the record regardless is over-permissive in the way that "
        f"matters -- the data lands in the log lake"
    )
    failed = _paged_keys(s3, bucket, gated + "-err/")
    assert failed == [], (
        f"the CloudWatchLogProcessing stream wrote {len(failed)} objects under its "
        f"ErrorOutputPrefix ({failed!r}); the refusal happened at the API, so nothing should "
        f"have been buffered and then diverted"
    )

    # --- ...while the identical bytes on the control leg DID land.
    assert open_body[:2] == _GZIP_MAGIC, (
        f"the unprocessed stream's object does not start with the gzip magic; got "
        f"{open_body[:2]!r}. It declares no processing, so it must store what it was handed"
    )
    open_text = gzip.decompress(open_body).decode("utf-8")
    assert direct_marker in open_text, (
        f"the unprocessed stream accepted the direct PutRecord (RecordId "
        f"{accepted['RecordId']!r}) but marker {direct_marker!r} is absent from its S3 object, "
        f"so the positive control did not actually deliver and the absence above proves nothing"
    )
    assert '"messageType":"DATA_MESSAGE"' in open_text, (
        f"the unprocessed stream's object does not contain a verbatim DATA_MESSAGE envelope; "
        f"object begins {open_text[:200]!r}"
    )
    for m in messages:
        assert m in open_text, (
            f"the unprocessed stream is missing subscription-filter message {m!r}; it must "
            f"carry both sources' records, which is what makes it the control"
        )

    # --- The one difference, described back by the service.
    gated_processing = (gated_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
                        ["ProcessingConfiguration"])
    assert "CloudWatchLogProcessing" in [p["Type"] for p in gated_processing["Processors"]], (
        f"the refusing stream's processors are "
        f"{[p['Type'] for p in gated_processing['Processors']]!r}; CloudWatchLogProcessing is "
        f"the declaration under test and must be present"
    )
    open_processing = (open_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
                       ["ProcessingConfiguration"])
    assert open_processing["Enabled"] is False, (
        f"the control stream reports ProcessingConfiguration.Enabled "
        f"{open_processing['Enabled']!r}; exactly one thing may differ between the two streams"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
