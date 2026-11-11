"""firehose-http-endpoint-request-envelope-conforms-to-the-documented-protocol."""
from __future__ import annotations

import base64
import io
import json
import re
import secrets
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-http-endpoint-request-envelope-conforms-to-the-documented-protocol"
GROUP = "data-delivery"
SERVICES = ["firehose", "lambda", "s3"]

_CAPTURE_PREFIX = "capture/"
_DELIVERED_PREFIX = "delivered/"
_ERROR_PREFIX = "err/"

_RECORD_COUNT = 3
_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_RETRY = {"DurationInSeconds": 60}

_CAPTURE_BUDGET_S = 300.0
_ABSENCE_MULTIPLIER = 3.0
_POLL_INTERVAL_S = 5.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0
_FN_ACTIVE_BUDGET_S = 120.0

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# The endpoint records the request Firehose actually sent (headers and raw body) into S3,
# because no Firehose API reports what it put on the wire, then answers with the documented
# success envelope. Lambda function URLs deliver header names lowercased.
_HANDLER = '''
import base64
import hmac
import json
import os
import time
import uuid

import boto3

_S3 = boto3.client("s3")
BUCKET = os.environ["CAPTURE_BUCKET"]
PREFIX = os.environ["CAPTURE_PREFIX"]
ACCESS_KEY = os.environ["ACCESS_KEY"]


def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    # Firehose authenticates with the access key configured on the destination; any other caller gets 403.
    if not hmac.compare_digest(headers.get("x-amz-firehose-access-key", "").encode(), ACCESS_KEY.encode()):
        return {"statusCode": 403, "body": "forbidden"}
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    _S3.put_object(
        Bucket=BUCKET,
        Key=PREFIX + str(uuid.uuid4()) + ".json",
        Body=json.dumps({"headers": headers, "body": raw}).encode("utf-8"),
    )
    # The request id comes from the HEADER, which the spec guarantees on every request. The
    # body is captured verbatim above and the CHECK -- not this handler -- decides whether it
    # conforms, so the handler needs no error handling and swallows nothing.
    request_id = headers.get("x-amz-firehose-request-id", "")
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"requestId": request_id, "timestamp": int(time.time() * 1000)}),
    }
'''


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing",
      "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Firehose's HTTP-endpoint request matches the documented header and body envelope.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/httpdeliveryrequestresponse.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    access_key = secrets.token_urlsafe(32)
    url = _create_capture_endpoint(ctx, bucket, access_key)

    attr_name = "sim2real-attribute"
    attr_value = ctx.unique_name("attr-")
    delivery_role = _create_firehose_role(ctx, bucket)

    stream = _create_http_stream(
        ctx,
        bucket=bucket,
        role_arn=delivery_role,
        url=url,
        access_key=access_key,
        common_attributes=[{"AttributeName": attr_name, "AttributeValue": attr_value}],
    )
    desc = _wait_active(ctx, stream)
    stream_arn = desc["DeliveryStreamARN"]
    assert stream_arn.startswith("arn:") and stream.rsplit("/", 1)[-1] in stream_arn, (
        f"DescribeDeliveryStream reported DeliveryStreamARN {stream_arn!r}, which does not "
        f"look like an ARN naming {stream!r}"
    )

    http_desc = desc["Destinations"][0]["HttpEndpointDestinationDescription"]
    assert http_desc["EndpointConfiguration"]["Url"] == url, (
        f"the stream reports HTTP endpoint Url "
        f"{http_desc['EndpointConfiguration']['Url']!r}, expected {url!r}"
    )

    nonce = ctx.unique_name("http-")
    records = [
        {"Data": f"{nonce}|record|{i:02d}|{'y' * (i * 5)}".encode()}
        for i in range(_RECORD_COUNT)
    ]
    put_started_ms = int(time.time() * 1000)
    resp = firehose.put_record_batch(DeliveryStreamName=stream, Records=records)
    assert resp["FailedPutCount"] == 0, (
        f"PutRecordBatch reported FailedPutCount {resp['FailedPutCount']}, expected 0. "
        f"Response: {resp['RequestResponses']!r}"
    )

    # The terminal read is at the consumer (the objects the endpoint wrote), not PutRecordBatch.
    t0 = time.monotonic()
    captures = _poll_until(
        lambda: _read_captures(ctx, bucket),
        lambda caps: _decoded_records(caps) >= {r["Data"] for r in records},
        budget_s=_CAPTURE_BUDGET_S,
        description=(
            f"the HTTP endpoint receives all {_RECORD_COUNT} records (it writes each request "
            f"it gets to s3://{bucket}/{_CAPTURE_PREFIX})"
        ),
    )
    positive_latency_s = max(time.monotonic() - t0, 1.0)

    # ---- the envelope ----
    for capture in captures:
        headers = capture["headers"]
        body_text = capture["body"]

        assert headers.get("x-amz-firehose-protocol-version") == "1.0", (
            f"the request's X-Amz-Firehose-Protocol-Version header is "
            f"{headers.get('x-amz-firehose-protocol-version')!r}, expected '1.0'. Headers "
            f"seen: {sorted(headers)!r}"
        )
        request_id = headers.get("x-amz-firehose-request-id", "")
        assert _GUID_RE.match(request_id), (
            f"the request's X-Amz-Firehose-Request-Id header is {request_id!r}, expected an "
            f"opaque GUID in 8-4-4-4-12 hexadecimal form"
        )
        # Derived from the ARN the service reported, not a literal.
        assert headers.get("x-amz-firehose-source-arn") == stream_arn, (
            f"the request's X-Amz-Firehose-Source-Arn header is "
            f"{headers.get('x-amz-firehose-source-arn')!r}, expected the ARN the service "
            f"itself reported for this stream, {stream_arn!r}"
        )
        assert headers.get("x-amz-firehose-access-key") == access_key, (
            "the request's X-Amz-Firehose-Access-Key header differs from the configured key; "
            "Firehose must copy it verbatim, without interpreting or re-encoding it"
        )
        assert headers.get("content-type") == "application/json", (
            f"the request's Content-Type header is {headers.get('content-type')!r}, expected "
            f"'application/json'"
        )
        assert "content-encoding" not in headers, (
            f"the request carries a Content-Encoding header "
            f"({headers.get('content-encoding')!r}) although RequestConfiguration."
            f"ContentEncoding is NONE; the header must be absent altogether when compression "
            f"is off"
        )
        common = json.loads(headers["x-amz-firehose-common-attributes"])
        assert common == {"commonAttributes": {attr_name: attr_value}}, (
            f"the request's X-Amz-Firehose-Common-Attributes header decoded to {common!r}, "
            f"expected exactly "
            f"{{'commonAttributes': {{{attr_name!r}: {attr_value!r}}}}} -- the attributes "
            f"configured on the stream"
        )

        body = json.loads(body_text)
        assert body["requestId"] == request_id, (
            f"the body's requestId is {body['requestId']!r} but the "
            f"X-Amz-Firehose-Request-Id header is {request_id!r}; the spec duplicates the "
            f"header value into the body and the two must agree"
        )
        assert isinstance(body["timestamp"], int), (
            f"the body's timestamp is {body['timestamp']!r} of type "
            f"{type(body['timestamp']).__name__}, expected an integer number of milliseconds "
            f"since the epoch"
        )
        now_ms = int(time.time() * 1000)
        assert put_started_ms - 300_000 <= body["timestamp"] <= now_ms + 300_000, (
            f"the body's timestamp {body['timestamp']} is not within 5 minutes of the run: "
            f"the records were put at {put_started_ms} and it is now {now_ms}"
        )
        assert isinstance(body["records"], list) and body["records"], (
            f"the body's records member is {body['records']!r}, expected a non-empty array"
        )
        for item in body["records"]:
            assert set(item) == {"data"}, (
                f"a records[] entry has members {sorted(item)!r}, expected exactly ['data'] -- "
                f"Firehose must not add fields of its own to the record envelope"
            )
            base64.b64decode(item["data"], validate=True)

    # Exactly the bytes that were put, nothing added, nothing dropped.
    delivered = _decoded_records(captures)
    expected = {r["Data"] for r in records}
    assert delivered == expected, (
        f"the endpoint received {sorted(delivered)!r} but {sorted(expected)!r} were put. "
        f"records[].data must base64-decode to the record bytes with no envelope and no "
        f"appended delimiter"
    )

    # A conforming 200 is accepted: nothing reaches the error or backup prefix and the capture
    # set stays unchanged (no retry of an acknowledged batch). The hold is scaled from the
    # measured delivery latency rather than a bare sleep.
    hold_s = min(positive_latency_s * _ABSENCE_MULTIPLIER, 120.0)
    hold_end = time.monotonic() + hold_s
    cycles = 0
    while time.monotonic() < hold_end:
        stray = _all_keys(ctx, bucket, _ERROR_PREFIX)
        assert stray == [], (
            f"{len(stray)} objects appeared under s3://{bucket}/{_ERROR_PREFIX} after the "
            f"endpoint answered 200 with the documented success envelope, "
            f"{time.monotonic() - (hold_end - hold_s):.0f}s into a {hold_s:.0f}s hold "
            f"(>= {_ABSENCE_MULTIPLIER}x the measured {positive_latency_s:.0f}s delivery "
            f"latency): {stray!r}. A conforming 200 must not be treated as a delivery failure"
        )
        backup = _all_keys(ctx, bucket, _DELIVERED_PREFIX)
        assert backup == [], (
            f"{len(backup)} objects appeared under s3://{bucket}/{_DELIVERED_PREFIX} although "
            f"S3BackupMode is FailedDataOnly and no delivery failed: {backup!r}"
        )
        again = _decoded_records(_read_captures(ctx, bucket))
        assert again == expected, (
            f"the endpoint's capture set changed during the hold window: it now holds "
            f"{sorted(again)!r}, expected the unchanged {sorted(expected)!r}. A 200 whose "
            f"requestId matches the request must end the delivery attempt, not start a retry"
        )
        cycles += 1
        time.sleep(_POLL_INTERVAL_S)
    assert cycles >= 2, (
        f"the absence hold ran only {cycles} observation cycles over {hold_s:.0f}s; at least "
        f"two identical reads are needed for the freeze detector to mean anything"
    )


def _decoded_records(captures: list[dict]) -> set[bytes]:
    out: set[bytes] = set()
    for capture in captures:
        body = json.loads(capture["body"])
        for item in body["records"]:
            out.add(base64.b64decode(item["data"]))
    return out


def _read_captures(ctx, bucket: str) -> list[dict]:
    s3 = ctx.client("s3")
    out: list[dict] = []
    for key in _all_keys(ctx, bucket, _CAPTURE_PREFIX):
        out.append(json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read()))
    return out


def _poll_until(probe, predicate, *, budget_s: float, description: str):
    """Poll until predicate holds; RAISE on timeout, never return the last value."""
    end = time.monotonic() + budget_s
    last = None
    while time.monotonic() < end:
        last = probe()
        if predicate(last):
            return last
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"DATAPLANE_UNIMPLEMENTED?: {description} did not happen within {budget_s}s. A target "
        f"that accepts an HttpEndpointDestinationConfiguration and never issues an HTTPS "
        f"request has no HTTP delivery path at all. Last observation: {last!r}"
    )


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-http-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Bounded at 30 s: all of this check's teardowns share a 60 s cleanup bound."""
    s3 = ctx.client("s3")
    end = time.monotonic() + 30.0
    while time.monotonic() < end:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            if not resp.get("IsTruncated"):
                break
            token = resp["NextContinuationToken"]
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "BucketNotEmpty":
                raise
            time.sleep(3.0)
    raise AssertionError(f"bucket {bucket!r} could not be emptied and deleted within 30s")


def _create_capture_endpoint(ctx, bucket: str, access_key: str) -> str:
    """A Lambda function URL that records every request carrying the stream's access key and answers with the
    documented success envelope; any other caller gets 403. Returns the https URL."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-fh-http-fnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description=f"sim2real-behav {CHECK} capture endpoint",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="capture",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/{_CAPTURE_PREFIX}*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "arn:aws:logs:*:*:*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="capture"))

    fn = ctx.unique_name("sim2real-fh-http-fn-")
    # A freshly created role is eventually consistent, so CreateFunction transiently answers
    # InvalidParameterValueException ('The role defined for the function cannot be assumed').
    end = time.monotonic() + _CREATE_BUDGET_S
    last = None
    while time.monotonic() < end:
        try:
            ctx.on_cleanup(lambda _n=fn: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _make_zip(_HANDLER)},
                Timeout=30,
                Environment={
                    "Variables": {
                        "CAPTURE_BUCKET": bucket,
                        "CAPTURE_PREFIX": _CAPTURE_PREFIX,
                        "ACCESS_KEY": access_key,
                    }
                },
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(5.0)
    else:
        raise AssertionError(
            f"CreateFunction({fn!r}) never succeeded within {_CREATE_BUDGET_S}s; last error "
            f"{last}"
        )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))

    fn_end = time.monotonic() + _FN_ACTIVE_BUDGET_S
    state = None
    while time.monotonic() < fn_end:
        state = lam.get_function_configuration(FunctionName=fn)["State"]
        if state == "Active":
            break
        assert state == "Pending", (
            f"lambda function {fn!r} reported State {state!r}; Pending is the only admissible "
            f"transient on the way to Active"
        )
        time.sleep(3.0)
    else:
        raise AssertionError(
            f"lambda function {fn!r} never became Active within {_FN_ACTIVE_BUDGET_S}s (last "
            f"state {state!r})"
        )

    url = lam.create_function_url_config(FunctionName=fn, AuthType="NONE")["FunctionUrl"]
    assert url.startswith("https://"), (
        f"CreateFunctionUrlConfig returned {url!r}; Firehose supports https destinations only"
    )
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=fn))
    # Two grants, per Lambda's NONE-auth function URL policy docs: InvokeFunctionUrl alone 403s
    # at Lambda's gatekeeper before the handler runs; InvokeFunction scoped to function-URL
    # invocations is also required.
    lam.add_permission(
        FunctionName=fn,
        StatementId="sim2real-fh-http-invoke-url",
        Action="lambda:InvokeFunctionUrl",
        Principal="*",
        FunctionUrlAuthType="NONE",
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=fn, StatementId="sim2real-fh-http-invoke-url"
        )
    )
    lam.add_permission(
        FunctionName=fn,
        StatementId="sim2real-fh-http-invoke-fn",
        Action="lambda:InvokeFunction",
        Principal="*",
        InvokedViaFunctionUrl=True,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=fn, StatementId="sim2real-fh-http-invoke-fn"
        )
    )
    return url


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-http-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description=f"sim2real-behav {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:AbortMultipartUpload",
                            "s3:GetBucketLocation",
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:ListBucketMultipartUploads",
                            "s3:PutObject",
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{bucket}",
                            f"arn:aws:s3:::{bucket}/*",
                        ],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="s3-write"))
    return arn


def _create_http_stream(
    ctx, *, bucket: str, role_arn: str, url: str, access_key: str, common_attributes: list
) -> str:
    """Bounded retry past the transient InvalidArgumentException a freshly created,
    eventually consistent delivery role produces. Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-http-")
    end = time.monotonic() + _CREATE_BUDGET_S
    last = None
    while time.monotonic() < end:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                HttpEndpointDestinationConfiguration={
                    "EndpointConfiguration": {
                        "Url": url,
                        "Name": "sim2real-capture",
                        "AccessKey": access_key,
                    },
                    "BufferingHints": dict(_BUFFER),
                    "RequestConfiguration": {
                        "ContentEncoding": "NONE",
                        "CommonAttributes": common_attributes,
                    },
                    "RoleARN": role_arn,
                    "RetryOptions": dict(_RETRY),
                    "S3BackupMode": "FailedDataOnly",
                    "S3Configuration": {
                        "RoleARN": role_arn,
                        "BucketARN": f"arn:aws:s3:::{bucket}",
                        "Prefix": _DELIVERED_PREFIX,
                        "ErrorOutputPrefix": (
                            _ERROR_PREFIX + "!{firehose:error-output-type}/"
                        ),
                        "BufferingHints": dict(_BUFFER),
                        "CompressionFormat": "UNCOMPRESSED",
                    },
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(lambda n=name: _delete_stream(firehose, n, {}))
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(5.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}) with an HTTP endpoint destination never succeeded "
        f"within {_CREATE_BUDGET_S}s; last error {last}. If the error names the URL rather "
        f"than the role, hypothesis H0 in this file's header is false"
    )


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


def _wait_active(ctx, name: str) -> dict:
    firehose = ctx.client("firehose")
    end = time.monotonic() + _ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < end:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        assert status in ("CREATING", "UPDATING"), (
            f"delivery stream {name!r} reported status {status!r} while waiting for ACTIVE"
        )
        time.sleep(4.0)
    raise AssertionError(
        f"delivery stream {name!r} never became ACTIVE within {_ACTIVE_BUDGET_S}s (last "
        f"status {status!r})"
    )


def _all_keys(ctx, bucket: str, prefix: str) -> list[str]:
    s3 = ctx.client("s3")
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


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
