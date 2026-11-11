"""subscription-filter-to-firehose-decompression-strips-cwl-envelope."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subscription-filter-to-firehose-decompression-strips-cwl-envelope"
GROUP = "e2e"
SERVICES = ["firehose", "logs", "s3"]

# Both streams use zero buffering, but CloudWatch Logs' hop to a brand-new Firehose destination
# can take well over 210 s on real AWS, so the cap is 360 s, bounded by the runner's budget.
_DELIVERY_BUDGET_S = 360.0
_POLL_INTERVAL_S = 2.0
_EVENT_COUNT = 12

# The gzip magic number. Asserted directly rather than only via gzip.decompress, so the
# failure message can say what the first bytes actually were.
_GZIP_MAGIC = b"\x1f\x8b"


def _paged_keys(s3, bucket: str, prefix: str) -> list[str]:
    """Every key under prefix, paginated."""
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


def _json_documents(text: str) -> list[dict]:
    """Split concatenated JSON documents: the unprocessed object holds the envelopes back to back
    with no separator, so json.loads over the whole payload fails."""
    decoder = json.JSONDecoder()
    docs: list[dict] = []
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx] in " \t\r\n":
            idx += 1
        if idx >= len(text):
            break
        doc, idx = decoder.raw_decode(text, idx)
        docs.append(doc)
    return docs


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_delivery_stream(ctx, name: str, config: dict) -> str:
    """CreateDeliveryStream, retried through InvalidArgumentException while Firehose cannot yet
    assume a freshly created role."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )["DeliveryStreamARN"]
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"CreateDeliveryStream({name}) past role propagation: the run budget ended first; not graded")
    raise AssertionError(f"CreateDeliveryStream({name}) never succeeded: {last}")


def _await_active(ctx, name: str) -> dict:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    status = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"delivery stream {name!r} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"delivery stream {name!r} never became ACTIVE (last status {status!r})")


def _put_subscription_filter(ctx, group: str, filter_name: str, arn: str, role_arn: str) -> None:
    """PutSubscriptionFilter, retried through InvalidParameterException: it delivers a test
    message to the destination first, which fails while the role propagates."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
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
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"PutSubscriptionFilter({filter_name}) past role propagation: the run budget ended first; not graded")
    raise AssertionError(f"PutSubscriptionFilter({filter_name}) never succeeded: {last}")


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A subscription filter into a Firehose stream with Decompression(GZIP) and
    CloudWatchLogProcessing lands only the newline-delimited messages in S3, while a control stream
    without processing lands the same events as one gzip'd DATA_MESSAGE envelope.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/writing-with-cloudwatch-logs-decompression.html
    """
    logs = ctx.client("logs")
    fh = ctx.client("firehose")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-f4fh-")
    fh_role = ctx.unique_name("sim2real-behav-f4fhrole-")
    logs_role = ctx.unique_name("sim2real-behav-f4lgrole-")
    group = ctx.unique_name("sim2real-behav-f4lg-")
    stream = ctx.unique_name("sim2real-behav-f4ls-")
    treated = ctx.unique_name("sim2real-behav-f4t-")
    control = ctx.unique_name("sim2real-behav-f4c-")
    treated_filter = ctx.unique_name("sim2real-f4tf-")
    control_filter = ctx.unique_name("sim2real-f4cf-")

    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )

    def _empty_and_delete_bucket(_b=bucket):
        # Firehose can still be flushing at cleanup, so empty in a loop and retry BucketNotEmpty.
        # Bounded at 40 s because all of a check's cleanups share a 60 s ceiling.
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
                time.sleep(2.0)
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
            "CompressionFormat": "UNCOMPRESSED",
            "ProcessingConfiguration": processing,
        }

    treated_arn = _create_delivery_stream(ctx, treated, _dest(treated, {
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
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=treated))
    control_arn = _create_delivery_stream(
        ctx, control, _dest(control, {"Enabled": False})
    )
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=control))

    treated_desc = _await_active(ctx, treated)
    control_desc = _await_active(ctx, control)

    logs_role_arn = iam.create_role(
        RoleName=logs_role,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "logs.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real-behav logs->firehose subscription role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=logs_role))
    iam.put_role_policy(
        RoleName=logs_role, PolicyName="firehose-write",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                           "Resource": [treated_arn, control_arn]}],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=logs_role, PolicyName="firehose-write")
    )

    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    _put_subscription_filter(ctx, group, treated_filter, treated_arn, logs_role_arn)
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=treated_filter)
    )
    _put_subscription_filter(ctx, group, control_filter, control_arn, logs_role_arn)
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=group, filterName=control_filter)
    )

    base_ms = int(time.time() * 1000)
    messages = [f"{group}-payload-{i:02d}" for i in range(_EVENT_COUNT)]
    written = {m: base_ms + i for i, m in enumerate(messages)}
    logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": written[m], "message": m} for m in messages],
    )

    # Poll for both payloads, not for any object: CloudWatch Logs sends a CONTROL_MESSAGE to a
    # new destination, which Firehose can flush alone before the events arrive.
    t0 = time.monotonic()
    delivery_budget_s = _budget_s(ctx, _DELIVERY_BUDGET_S)
    treated_keys: list[str] = []
    control_keys: list[str] = []
    treated_body = b""
    control_body = b""
    control_text = ""
    while time.monotonic() - t0 < delivery_budget_s:
        treated_keys = _paged_keys(s3, bucket, treated + "/")
        control_keys = _paged_keys(s3, bucket, control + "/")
        treated_body = _concat_objects(s3, bucket, treated_keys) if treated_keys else b""
        control_body = _concat_objects(s3, bucket, control_keys) if control_keys else b""
        control_text = ""
        if control_body[:2] == _GZIP_MAGIC:
            try:
                control_text = gzip.decompress(control_body).decode("utf-8")
            except (OSError, EOFError, UnicodeDecodeError):
                control_text = ""
        if (all(m in treated_body.decode("utf-8", "replace") for m in messages)
                and group in control_text):
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0
    if not (all(m in treated_body.decode("utf-8", "replace") for m in messages)
            and group in control_text) and _budget_spent(ctx):
        raise TimeoutError("both streams' payloads landing in S3: the run budget ended first; not graded")

    assert treated_keys and control_keys, (
        f"DATAPLANE_UNIMPLEMENTED: CloudWatch Logs -> Firehose -> S3 delivered nothing in "
        f"{waited:.0f}s. {_EVENT_COUNT} events were written to log group {group!r}; the "
        f"processed stream's prefix holds {len(treated_keys)} objects and the unprocessed "
        f"control stream's prefix holds {len(control_keys)}. Real AWS delivered both within "
        f"106 s on the same shape. A target that accepts PutSubscriptionFilter with a Firehose "
        f"destination and never writes to S3 has no delivery pipeline at all."
    )

    # 1. The processed object is NOT gzip -- AWS did the decompression.
    assert treated_body[:2] != _GZIP_MAGIC, (
        f"the processed stream's object still starts with the gzip magic "
        f"{treated_body[:2]!r}: the Decompression processor did not run"
    )
    decompressed_treated = None
    try:
        decompressed_treated = gzip.decompress(treated_body)
    except (OSError, EOFError):
        pass
    assert decompressed_treated is None, (
        f"the processed stream's object is still valid gzip ({len(treated_body)} bytes in, "
        f"{len(decompressed_treated or b'')} out): Decompression(GZIP) was declared and "
        f"described back by the service but never applied"
    )

    # 2. The control object IS gzip -- so assertion 1 grades stripping, not never-wrapping.
    assert control_body[:2] == _GZIP_MAGIC, (
        f"the unprocessed control stream's object does not start with the gzip magic; got "
        f"{control_body[:2]!r}. CloudWatch Logs must gzip what it hands a subscription "
        f"destination, otherwise the processed path had nothing to decompress and assertion 1 "
        f"is vacuous"
    )
    control_text = gzip.decompress(control_body).decode("utf-8")

    # 3. The control path carries the full CloudWatch Logs envelope.
    docs = _json_documents(control_text)
    data_docs = [d for d in docs if d.get("logGroup") == group]
    assert data_docs, (
        f"none of the {len(docs)} JSON documents in the unprocessed object names log group "
        f"{group!r}; documents carried logGroup values "
        f"{sorted({d.get('logGroup') for d in docs})!r}"
    )
    for doc in data_docs:
        assert doc["messageType"] == "DATA_MESSAGE", (
            f"an envelope for {group!r} has messageType {doc['messageType']!r}, expected "
            f"DATA_MESSAGE"
        )
        assert doc["owner"] == account, (
            f"envelope owner is {doc['owner']!r}, expected the log group's account {account!r}"
        )
        assert doc["logStream"] == stream, (
            f"envelope logStream is {doc['logStream']!r}, expected {stream!r}"
        )
        assert doc["subscriptionFilters"] == [control_filter], (
            f"envelope subscriptionFilters is {doc['subscriptionFilters']!r}, expected exactly "
            f"[{control_filter!r}] -- the envelope must name the filter that delivered it"
        )

    envelope_events = [e for d in data_docs for e in d["logEvents"]]
    assert len(envelope_events) == _EVENT_COUNT, (
        f"the unprocessed envelopes carry {len(envelope_events)} log events, expected exactly "
        f"the {_EVENT_COUNT} written"
    )
    assert sorted(e["message"] for e in envelope_events) == sorted(messages), (
        f"the unprocessed envelopes' messages are "
        f"{sorted(e['message'] for e in envelope_events)!r}, expected {sorted(messages)!r}"
    )
    assert {e["message"]: e["timestamp"] for e in envelope_events} == written, (
        f"the envelope re-stamped the events: got "
        f"{ {e['message']: e['timestamp'] for e in envelope_events} !r}, wrote {written!r}"
    )
    envelope_ids = [e["id"] for e in envelope_events]
    assert len(set(envelope_ids)) == _EVENT_COUNT and all(envelope_ids), (
        f"the envelope's per-event ids are not {_EVENT_COUNT} distinct non-empty strings: "
        f"{envelope_ids!r}"
    )

    # 4. The processed object is the twelve MESSAGES, newline-delimited, in order.
    treated_text = treated_body.decode("utf-8")
    lines = [ln for ln in treated_text.split("\n") if ln]
    assert lines == messages, (
        f"the processed object's non-empty lines are {lines!r}; expected exactly the "
        f"{_EVENT_COUNT} messages written, in order: {messages!r}"
    )

    # 5. The envelope is GONE from the processed object -- not merely reordered.
    for needle in ("messageType", "DATA_MESSAGE", "logEvents", "subscriptionFilters"):
        assert needle not in treated_text, (
            f"the processed object still contains the envelope member {needle!r}: "
            f"CloudWatchLogProcessing(DataMessageExtraction=true) passed the envelope through "
            f"instead of extracting the log events from it. Object begins "
            f"{treated_text[:200]!r}"
        )

    # 6. So are the per-event id and timestamp: extraction keeps `message` only.
    for eid in envelope_ids:
        assert eid not in treated_text, (
            f"the processed object contains the envelope's per-event id {eid!r}; measured real "
            f"AWS emits the message strings alone, so the id must not survive extraction"
        )
    assert str(base_ms) not in treated_text, (
        f"the processed object contains the ingest timestamp {base_ms!r}; measured real AWS "
        f"drops logEvents[].timestamp along with the envelope"
    )

    # 7. The CONTROL_MESSAGE health check is dropped by extraction. Its presence on the control
    # path is not asserted: the health-check cadence is not documented.
    assert "CWL CONTROL MESSAGE" not in treated_text, (
        f"the processed object contains CloudWatch Logs' CONTROL_MESSAGE health-check text; "
        f"CloudWatchLogProcessing must drop non-DATA_MESSAGE records. Object begins "
        f"{treated_text[:200]!r}"
    )

    # 8. The service describes back the pipeline it actually ran, in the declared order.
    processing = (treated_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
                  ["ProcessingConfiguration"])
    assert processing["Enabled"] is True, (
        f"the processed stream reports ProcessingConfiguration.Enabled "
        f"{processing['Enabled']!r}"
    )
    assert [p["Type"] for p in processing["Processors"]] == [
        "Decompression", "CloudWatchLogProcessing", "AppendDelimiterToRecord"
    ], (
        f"the processed stream's processors are "
        f"{[p['Type'] for p in processing['Processors']]!r}; the order is the transformation "
        f"order and Decompression must precede CloudWatchLogProcessing"
    )
    assert processing["Processors"][0]["Parameters"] == [
        {"ParameterName": "CompressionFormat", "ParameterValue": "GZIP"}
    ], (
        f"the Decompression processor's parameters came back "
        f"{processing['Processors'][0]['Parameters']!r}, expected CompressionFormat=GZIP"
    )
    control_processing = (control_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
                         ["ProcessingConfiguration"])
    assert control_processing["Enabled"] is False, (
        f"the control stream reports ProcessingConfiguration.Enabled "
        f"{control_processing['Enabled']!r}; it must be disabled for the comparison to mean "
        f"anything"
    )

    # 9. Neither stream diverted anything to its error-output prefix.
    for name in (treated, control):
        failed = _paged_keys(s3, bucket, name + "-err/")
        assert failed == [], (
            f"delivery stream {name!r} wrote {len(failed)} objects under its "
            f"ErrorOutputPrefix: {failed!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
