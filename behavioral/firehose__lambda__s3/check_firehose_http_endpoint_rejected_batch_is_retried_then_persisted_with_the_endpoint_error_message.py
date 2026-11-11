"""firehose-http-endpoint-rejected-batch-is-retried-then-persisted-with-the-endpoint-error-message."""
from __future__ import annotations

import base64
import io
import json
import secrets
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "firehose-http-endpoint-rejected-batch-is-retried-then-persisted-with-the-endpoint-error-message"
)
GROUP = "data-delivery"
SERVICES = ["firehose", "lambda", "s3"]

_CAPTURE_PREFIX = "capture/"
_RECORD_COUNT = 2
_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_RETRY_SECONDS = 60
_MIN_ATTEMPTS = 2

_CAPTURE_BUDGET_S = 300.0
_PERSIST_BUDGET_S = 360.0
_POLL_INTERVAL_S = 5.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0
_FN_ACTIVE_BUDGET_S = 120.0

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
GOOD_KEY = os.environ["GOOD_KEY"]
BAD_KEY = os.environ["BAD_KEY"]
ERROR_MESSAGE = os.environ["ERROR_MESSAGE"]


def handler(event, context):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    # Only the two per-run access keys configured on the check's streams are served; any other caller gets 403.
    access_key = headers.get("x-amz-firehose-access-key", "").encode()
    accepted = hmac.compare_digest(access_key, GOOD_KEY.encode())
    if not accepted and not hmac.compare_digest(access_key, BAD_KEY.encode()):
        return {"statusCode": 403, "body": "forbidden"}
    request_id = headers.get("x-amz-firehose-request-id", "")
    _S3.put_object(
        Bucket=BUCKET,
        Key=PREFIX + ("ok/" if accepted else "bad/") + str(uuid.uuid4()) + ".json",
        Body=json.dumps(
            {
                "headers": headers,
                "body": raw,
                "accepted": accepted,
                "requestId": request_id,
                "receivedAtMs": int(time.time() * 1000),
            }
        ).encode("utf-8"),
    )
    body = {"requestId": request_id, "timestamp": int(time.time() * 1000)}
    if accepted:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body),
        }
    # The documented failure envelope: a 5XX status with requestId, timestamp and
    # errorMessage. 500 is a RETRIABLE code per the spec (only 413 is permanent), which is
    # what makes the retry leg below observable.
    body["errorMessage"] = ERROR_MESSAGE
    return {
        "statusCode": 500,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
'''


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A 500 from the HTTP endpoint is retried, then the batch is persisted with its error.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/httpdeliveryrequestresponse.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    good_key = secrets.token_urlsafe(32)
    bad_key = secrets.token_urlsafe(32)
    error_message = f"sim2real-endpoint-refused-{ctx.unique_name('e-')}"

    url = _create_endpoint(ctx, bucket, good_key=good_key, bad_key=bad_key, error_message=error_message)
    role_arn = _create_firehose_role(ctx, bucket)

    # The two legs differ in ONE thing: the access key the endpoint checks.
    control = _create_http_stream(
        ctx, bucket=bucket, role_arn=role_arn, url=url, access_key=good_key, leg="ok"
    )
    treated = _create_http_stream(
        ctx, bucket=bucket, role_arn=role_arn, url=url, access_key=bad_key, leg="bad"
    )
    _wait_active(ctx, control)
    _wait_active(ctx, treated)

    nonce = ctx.unique_name("fail-")
    records = [
        {"Data": f"{nonce}|record|{i:02d}".encode()} for i in range(_RECORD_COUNT)
    ]
    for leg, stream in (("control", control), ("treated", treated)):
        resp = firehose.put_record_batch(DeliveryStreamName=stream, Records=records)
        assert resp["FailedPutCount"] == 0, (
            f"PutRecordBatch on the {leg} leg reported FailedPutCount "
            f"{resp['FailedPutCount']}, expected 0 -- the producer must accept the records "
            f"regardless of what the destination later does with them. Response: "
            f"{resp['RequestResponses']!r}"
        )

    # ---- beat 1: the POSITIVE CONTROL succeeds on the same endpoint in the same instant ----
    t0 = time.monotonic()
    ok_captures = _poll_until(
        lambda: _read_captures(ctx, bucket, "ok/"),
        lambda caps: _decoded(caps) >= {r["Data"] for r in records},
        budget_s=_CAPTURE_BUDGET_S,
        description=(
            f"the control leg's records reach the endpoint (captured under "
            f"s3://{bucket}/{_CAPTURE_PREFIX}ok/)"
        ),
    )
    control_latency_s = max(time.monotonic() - t0, 1.0)
    assert all(c["accepted"] is True for c in ok_captures), (
        f"the control leg's captured requests report accepted="
        f"{sorted({c['accepted'] for c in ok_captures})!r}; every one must be True, because "
        f"the endpoint decides on the access key and the control leg carries the good one"
    )

    # ---- beat 2: the treated leg's batch is REFUSED and RETRIED ----
    bad_captures = _poll_until(
        lambda: _read_captures(ctx, bucket, "bad/"),
        lambda caps: len(caps) >= _MIN_ATTEMPTS,
        budget_s=_CAPTURE_BUDGET_S + _RETRY_SECONDS,
        description=(
            f"the treated leg's batch is attempted at least {_MIN_ATTEMPTS} times (the "
            f"endpoint answers 500, which the spec classifies as retriable)"
        ),
    )
    assert all(c["accepted"] is False for c in bad_captures), (
        f"the treated leg's captured requests report accepted="
        f"{sorted({c['accepted'] for c in bad_captures})!r}; every one must be False"
    )
    assert len(bad_captures) >= _MIN_ATTEMPTS, (
        f"the endpoint saw {len(bad_captures)} attempt(s) for the refused batch, expected at "
        f"least {_MIN_ATTEMPTS}. A 500 is retriable, so Firehose must reattempt within the "
        f"{_RETRY_SECONDS}s RetryOptions.DurationInSeconds window; a target that gives up "
        f"after one try, or never retries at all, diverges here"
    )
    # The retried attempts really are the SAME batch, not new data.
    assert _decoded(bad_captures) == {r["Data"] for r in records}, (
        f"the refused attempts carried {sorted(_decoded(bad_captures))!r}, expected exactly "
        f"the {_RECORD_COUNT} records that were put, {sorted(r['Data'] for r in records)!r}. "
        f"A retry must resend the same batch"
    )
    # The attempts are spread over time, not fired in one burst -- the spec's backoff.
    received = sorted(c["receivedAtMs"] for c in bad_captures)
    assert received[-1] - received[0] >= 1000, (
        f"all {len(bad_captures)} refused attempts arrived within "
        f"{received[-1] - received[0]}ms of each other; the documented backoff starts at 1 s, "
        f"so successive attempts must be at least ~1 s apart. Timestamps: {received!r}"
    )

    # ---- beat 3: the batch is PERSISTED, with the endpoint's own error message ----
    persisted = _poll_until(
        lambda: _all_keys(ctx, bucket, "err/") + _all_keys(ctx, bucket, "backup/"),
        lambda ks: len(ks) > 0,
        budget_s=_PERSIST_BUDGET_S,
        description=(
            f"the exhausted batch is persisted under s3://{bucket}/err/ or "
            f"s3://{bucket}/backup/"
        ),
    )
    blob = b"".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in persisted
    )
    # The expected value is a string generated in this run, returned by the endpoint and carried back through
    # Firehose.
    assert error_message.encode() in blob, (
        f"the persisted object(s) {persisted!r} ({len(blob)} bytes) do not contain the "
        f"errorMessage the endpoint returned, {error_message!r}. The spec says the last "
        f"instance of the error message is copied to the error output location. Object begins "
        f"{blob[:300]!r}"
    )
    # The original record must be recoverable from it, plainly or base64-encoded (Firehose
    # error objects carry a `rawData` base64 member for metadata-extraction failures).
    marker = records[0]["Data"]
    assert marker in blob or base64.b64encode(marker) in blob, (
        f"the persisted object(s) {persisted!r} contain neither the refused record "
        f"{marker!r} nor its base64 encoding; a failed batch must be recoverable from the "
        f"error output. Object begins {blob[:300]!r}"
    )
    # The weaker-footed half, asserted separately so a wrong prefix does not invalidate
    # the claim above.
    assert any(k.startswith("err/http-endpoint-failed/") for k in persisted), (
        f"none of the persisted keys {persisted!r} starts with "
        f"'err/http-endpoint-failed/'; the ErrorOutputPrefix declares "
        f"'!{{firehose:error-output-type}}' and an HTTP endpoint delivery failure must "
        f"evaluate it to 'http-endpoint-failed'"
    )

    # ---- beat 4: the control leg was NOT persisted -- the refusal was specific ----
    # Absence bounded by the control leg's OWN measured latency on the same wiring, and the
    # treated leg has ALREADY been persisted, which proves the persistence path works.
    hold_s = min(control_latency_s * 3.0, 120.0)
    hold_end = time.monotonic() + hold_s
    cycles = 0
    while time.monotonic() < hold_end:
        for key in _all_keys(ctx, bucket, "err/") + _all_keys(ctx, bucket, "backup/"):
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            assert error_message.encode() in body, (
                f"the persisted object {key!r} does not carry the treated leg's error "
                f"message; the only data persisted may be the treated leg's refused batch, "
                f"but this object came from somewhere else. It begins {body[:300]!r}"
            )
        cycles += 1
        time.sleep(_POLL_INTERVAL_S)
    assert cycles >= 2, (
        f"the absence hold ran only {cycles} observation cycles over {hold_s:.0f}s; at least "
        f"two identical reads are needed for the freeze detector to mean anything"
    )

    # ---- beat 5: restore. The identical batch, sent with the GOOD key, is accepted and
    # nothing new is persisted. This is the six-beat close: the refusal was about the one
    # thing that was broken, and it is reversible.
    before = set(_all_keys(ctx, bucket, "err/") + _all_keys(ctx, bucket, "backup/"))
    restore_nonce = ctx.unique_name("restore-")
    restore_records = [{"Data": f"{restore_nonce}|r|{i:02d}".encode()} for i in range(2)]
    firehose.put_record_batch(DeliveryStreamName=control, Records=restore_records)
    restored = _poll_until(
        lambda: _read_captures(ctx, bucket, "ok/"),
        lambda caps: _decoded(caps) >= {r["Data"] for r in restore_records},
        budget_s=_CAPTURE_BUDGET_S,
        description="the restored batch reaches the endpoint through the control leg",
    )
    assert all(c["accepted"] is True for c in restored), (
        f"the restored batch's captured requests report accepted="
        f"{sorted({c['accepted'] for c in restored})!r}; all must be True"
    )
    after = set(_all_keys(ctx, bucket, "err/") + _all_keys(ctx, bucket, "backup/"))
    assert after == before, (
        f"the restored, accepted batch added {sorted(after - before)!r} to the error output "
        f"location; an accepted delivery must persist nothing there"
    )


# ===== helpers =====


def _decoded(captures: list[dict]) -> set[bytes]:
    out: set[bytes] = set()
    for capture in captures:
        for item in json.loads(capture["body"])["records"]:
            out.add(base64.b64decode(item["data"]))
    return out


def _read_captures(ctx, bucket: str, leg: str) -> list[dict]:
    s3 = ctx.client("s3")
    out: list[dict] = []
    for key in _all_keys(ctx, bucket, _CAPTURE_PREFIX + leg):
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
        f"DATAPLANE_UNIMPLEMENTED?: {description} did not happen within {budget_s}s. Last "
        f"observation: {last!r}"
    )


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-hfail-")
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
    """Bounded at 30 s: this check registers many teardowns and the runner bounds ALL of a
    check's cleanups together at 60 s. If it overruns, the leak is a finding with the bucket
    name, not something to paper over."""
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


def _create_endpoint(ctx, bucket: str, *, good_key: str, bad_key: str, error_message: str) -> str:
    """One Lambda function URL that accepts the good access key, answers the bad one with a 500 error envelope,
    and refuses every other caller with 403."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-fh-hfail-fnrole-")
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
        Description=f"sim2real-behav {CHECK} endpoint",
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

    fn = ctx.unique_name("sim2real-fh-hfail-fn-")
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
                        "GOOD_KEY": good_key,
                        "BAD_KEY": bad_key,
                        "ERROR_MESSAGE": error_message,
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
    # Two separate grants, per the documented NONE-auth-type policy: InvokeFunctionUrl alone
    # 403s ("Forbidden" from Lambda itself, before the handler ever runs). InvokeFunction, scoped to
    # function-URL invocations only via InvokedViaFunctionUrl, is also required.
    lam.add_permission(
        FunctionName=fn,
        StatementId="sim2real-fh-hfail-invoke-url",
        Action="lambda:InvokeFunctionUrl",
        Principal="*",
        FunctionUrlAuthType="NONE",
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=fn, StatementId="sim2real-fh-hfail-invoke-url"
        )
    )
    lam.add_permission(
        FunctionName=fn,
        StatementId="sim2real-fh-hfail-invoke-fn",
        Action="lambda:InvokeFunction",
        Principal="*",
        InvokedViaFunctionUrl=True,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(
            FunctionName=fn, StatementId="sim2real-fh-hfail-invoke-fn"
        )
    )
    return url


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-hfail-role-")
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


def _delete_stream(firehose, name: str, timeout_s: float = 120.0) -> None:
    """Delete the stream and wait until it is gone: a DELETING stream is still listed."""
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            status = desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]
            raise AssertionError(f"stream {name} still {status} {timeout_s}s after DeleteDeliveryStream")
        time.sleep(2)


def _create_http_stream(
    ctx, *, bucket: str, role_arn: str, url: str, access_key: str, leg: str
) -> str:
    """Bounded retry past the transient InvalidArgumentException a freshly created,
    eventually consistent delivery role produces. Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-fh-hfail-{leg}-")
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
                        "Name": f"sim2real-{leg}",
                        "AccessKey": access_key,
                    },
                    "BufferingHints": dict(_BUFFER),
                    "RequestConfiguration": {"ContentEncoding": "NONE"},
                    "RoleARN": role_arn,
                    "RetryOptions": {"DurationInSeconds": _RETRY_SECONDS},
                    "S3BackupMode": "FailedDataOnly",
                    "S3Configuration": {
                        "RoleARN": role_arn,
                        "BucketARN": f"arn:aws:s3:::{bucket}",
                        "Prefix": "backup/",
                        "ErrorOutputPrefix": "err/!{firehose:error-output-type}/",
                        "BufferingHints": dict(_BUFFER),
                        "CompressionFormat": "UNCOMPRESSED",
                    },
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(lambda n=name: _delete_stream(firehose, n))
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(5.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}) with an HTTP endpoint destination never succeeded "
        f"within {_CREATE_BUDGET_S}s; last error {last}. If the error names the URL rather "
        f"than the role, Firehose does not accept this function URL as an HTTP endpoint"
    )


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
