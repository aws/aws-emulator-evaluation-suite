"""cloudwatch-logging-options-emits-the-s3-access-denied-error-while-the-healthy-twin-logs-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cloudwatch-logging-options-emits-the-s3-access-denied-error-while-the-healthy-twin-logs-nothing"
)
GROUP = "e2e"
SERVICES = ["firehose", "logs", "s3"]

_LOG_STREAM = "DestinationDelivery"
_OK_PREFIX = "ok/"
_DENIED_PREFIX = "denied/"
_POLICY_NAME = "s3-write"

_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_DELIVERY_BUDGET_S = 300.0
_LOG_BUDGET_S = 300.0
_RESTORE_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0

_EXPECTED_ERROR_CODE = "S3.AccessDenied"


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A denied S3 delivery logs S3.AccessDenied to the configured stream and writes nothing, while
    the healthy twin delivers and logs nothing; granting access then delivers the withheld record.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/monitoring-with-cloudwatch-logs.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    ok_group = _create_log_group(ctx, "ok")
    denied_group = _create_log_group(ctx, "denied")

    # One role, one broken thing: s3:PutObject is scoped to the OK prefix only, so the
    # treated stream's PutObject is denied and nothing else differs between the legs.
    role_name, role_arn = _create_firehose_role(
        ctx,
        bucket=bucket,
        allowed_prefixes=[_OK_PREFIX],
        log_group_arns=[
            f"arn:aws:logs:{ctx.region}:{account}:log-group:{ok_group}:*",
            f"arn:aws:logs:{ctx.region}:{account}:log-group:{denied_group}:*",
        ],
    )

    control = _create_stream(
        ctx, bucket, role_arn, prefix=_OK_PREFIX, log_group=ok_group
    )
    treated = _create_stream(
        ctx, bucket, role_arn, prefix=_DENIED_PREFIX, log_group=denied_group
    )
    control_desc = _wait_active(ctx, control)
    treated_desc = _wait_active(ctx, treated)

    for leg, desc, group in (
        ("control", control_desc, ok_group),
        ("treated", treated_desc, denied_group),
    ):
        options = desc["Destinations"][0]["ExtendedS3DestinationDescription"][
            "CloudWatchLoggingOptions"
        ]
        assert options["Enabled"] is True, (
            f"the {leg} stream reports CloudWatchLoggingOptions.Enabled "
            f"{options['Enabled']!r}, expected True"
        )
        assert options["LogGroupName"] == group, (
            f"the {leg} stream reports LogGroupName {options['LogGroupName']!r}, expected "
            f"{group!r}"
        )
        assert options["LogStreamName"] == _LOG_STREAM, (
            f"the {leg} stream reports LogStreamName {options['LogStreamName']!r}, expected "
            f"{_LOG_STREAM!r}"
        )

    nonce = ctx.unique_name("cwl-")
    payload = f"{CHECK}|{nonce}".encode()
    firehose.put_record(DeliveryStreamName=control, Record={"Data": payload})
    firehose.put_record(DeliveryStreamName=treated, Record={"Data": payload})

    # Positive control: the healthy leg delivers on the same role, bucket and buffering.
    t0 = time.monotonic()
    ok_keys = _poll_until(
        ctx,
        lambda: _all_keys(ctx, bucket, _OK_PREFIX),
        lambda ks: len(ks) > 0,
        budget_s=_DELIVERY_BUDGET_S,
        description=f"the permitted leg delivers an object under s3://{bucket}/{_OK_PREFIX}",
    )
    delivery_latency_s = max(time.monotonic() - t0, 1.0)
    ok_body = s3.get_object(Bucket=bucket, Key=ok_keys[0])["Body"].read()
    assert payload in ok_body, (
        f"the permitted leg's object s3://{bucket}/{ok_keys[0]} does not contain the record "
        f"that was put ({payload!r}); it holds {ok_body[:200]!r}"
    )

    # Error logging is sampled only at high failure rates; one failing record must be logged.
    t1 = time.monotonic()
    events = _poll_until(
        ctx,
        lambda: _log_events(ctx, denied_group),
        lambda evs: any(_error_code_of(e) == _EXPECTED_ERROR_CODE for e in evs),
        budget_s=_LOG_BUDGET_S,
        description=(
            f"CloudWatch Logs group {denied_group!r} receives a delivery-error event with "
            f"errorCode {_EXPECTED_ERROR_CODE!r}"
        ),
    )
    log_latency_s = max(time.monotonic() - t1, 1.0)
    codes = [_error_code_of(e) for e in events]
    assert _EXPECTED_ERROR_CODE in codes, (
        f"the denied leg's log group {denied_group!r} holds {len(events)} event(s) with "
        f"errorCodes {codes!r}; expected one to be {_EXPECTED_ERROR_CODE!r}. The delivery "
        f"role's inline policy permits s3:PutObject only under {_OK_PREFIX!r}, so writing "
        f"under {_DENIED_PREFIX!r} must be denied AND reported"
    )
    denied_event = next(e for e in events if _error_code_of(e) == _EXPECTED_ERROR_CODE)
    assert _LOG_STREAM == denied_event["logStreamName"], (
        f"the {_EXPECTED_ERROR_CODE} event was written to log stream "
        f"{denied_event['logStreamName']!r}, expected the configured {_LOG_STREAM!r}"
    )

    # Effect absent, read independently at the destination.
    stray = _all_keys(ctx, bucket, _DENIED_PREFIX)
    assert stray == [], (
        f"{len(stray)} objects landed under s3://{bucket}/{_DENIED_PREFIX} although the "
        f"delivery role has no s3:PutObject permission there: {stray!r}. The permitted leg "
        f"delivered in {delivery_latency_s:.0f}s on the same wiring, so the pipeline is "
        f"demonstrably live and this absence is a refusal, not a slow start"
    )

    # The healthy twin logs nothing. The hold is scaled from the treated leg's measured
    # time-to-log-event and re-read every cycle so a violation fails as soon as it appears.
    hold_s = min(max(log_latency_s * 3.0, 30.0), 120.0)
    hold_end = time.monotonic() + hold_s
    cycles = 0
    while time.monotonic() < hold_end:
        ok_events = _log_events(ctx, ok_group)
        assert ok_events == [], (
            f"the permitted leg's log group {ok_group!r} holds {len(ok_events)} event(s) "
            f"{[e['message'][:120] for e in ok_events]!r}; a delivery that SUCCEEDED must not "
            f"produce a delivery-error log event. Held {hold_s:.0f}s, calibrated at 3x the "
            f"{log_latency_s:.0f}s the denied leg took to log"
        )
        cycles += 1
        time.sleep(_POLL_INTERVAL_S)
    assert cycles >= 2, (
        f"the absence hold ran only {cycles} observation cycles over {hold_s:.0f}s; at least "
        f"two identical reads are needed for the freeze detector to mean anything"
    )

    # Restore: Firehose retries S3 delivery rather than dropping it (data is retained up to 24 h).
    # IAM propagation into the role session is slow, hence the generous restore budget.
    _put_role_policy(ctx, role_name, bucket, allowed_prefixes=[_OK_PREFIX, _DENIED_PREFIX])
    restored = _poll_until(
        ctx,
        lambda: _all_keys(ctx, bucket, _DENIED_PREFIX),
        lambda ks: len(ks) > 0,
        budget_s=_RESTORE_BUDGET_S,
        description=(
            f"after the delivery role is granted s3:PutObject under {_DENIED_PREFIX!r}, the "
            f"withheld record lands there"
        ),
    )
    restored_body = b"".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in restored
    )
    assert payload in restored_body, (
        f"after the permission was restored, s3://{bucket}/{_DENIED_PREFIX} holds "
        f"{restored!r} but none of it contains the withheld record {payload!r}; it holds "
        f"{restored_body[:200]!r}. Firehose must have RETAINED and retried the record, not "
        f"dropped it"
    )


def _error_code_of(event: dict) -> str:
    """The event's errorCode. The JSON shape is undocumented, so a non-JSON message degrades
    to a substring probe for the documented code rather than raising."""
    message = event["message"]
    try:
        parsed = json.loads(message)
    except (ValueError, TypeError):
        return _EXPECTED_ERROR_CODE if _EXPECTED_ERROR_CODE in message else ""
    if isinstance(parsed, dict) and isinstance(parsed.get("errorCode"), str):
        return parsed["errorCode"]
    return _EXPECTED_ERROR_CODE if _EXPECTED_ERROR_CODE in message else ""


def _log_events(ctx, group: str) -> list[dict]:
    """Every event in the group, across pages; [] when the group is empty."""
    logs = ctx.client("logs")
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"logGroupName": group, "limit": 100}
        if token:
            kwargs["nextToken"] = token
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as err:
            # The group is created by this check, so ResourceNotFound would be a real defect
            # and must surface; nothing is swallowed.
            raise AssertionError(
                f"FilterLogEvents on {group!r} failed with "
                f"{err.response['Error']['Code']}: {err.response['Error'].get('Message')!r}. "
                f"The group was created by this check and must be readable"
            ) from err
        out.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return out


def _poll_until(ctx, probe, predicate, *, budget_s: float, description: str):
    """Poll until predicate holds; RAISE on timeout, never return the last value."""
    left = ctx.time_left()
    end = time.monotonic() + (budget_s if left is None else max(1.0, min(budget_s, left - 5.0)))
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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-cwl-")
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
    """Bounded at 25 s: all of this check's teardowns share a 60 s cleanup bound."""
    s3 = ctx.client("s3")
    end = time.monotonic() + 25.0
    while time.monotonic() < end:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
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
    raise AssertionError(f"bucket {bucket!r} could not be emptied and deleted within 25s")


def _create_log_group(ctx, leg: str) -> str:
    """Firehose error logging configured through the API requires the group and stream to
    exist in advance."""
    logs = ctx.client("logs")
    name = ctx.unique_name(f"/sim2real/fh-cwl-{leg}-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    logs.create_log_stream(logGroupName=name, logStreamName=_LOG_STREAM)
    return name


def _s3_policy(bucket: str, allowed_prefixes: list[str]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BucketLevel",
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                ],
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "ObjectLevelScoped",
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetObject",
                    "s3:PutObject",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}/{p}*" for p in allowed_prefixes],
            },
        ],
    }


def _put_role_policy(ctx, role_name: str, bucket: str, *, allowed_prefixes: list[str]) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps(_s3_policy(bucket, allowed_prefixes)),
    )


def _create_firehose_role(
    ctx, *, bucket: str, allowed_prefixes: list[str], log_group_arns: list[str]
) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-cwl-role-")
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
    _put_role_policy(ctx, name, bucket, allowed_prefixes=allowed_prefixes)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=_POLICY_NAME))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="cwl-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "logs:PutLogEvents",
                        "Resource": log_group_arns,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="cwl-write"))
    return name, arn


def _create_stream(ctx, bucket: str, role_arn: str, *, prefix: str, log_group: str) -> str:
    """Bounded retry past the transient InvalidArgumentException a freshly created,
    eventually consistent delivery role produces. Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-cwl-")
    end = time.monotonic() + _CREATE_BUDGET_S
    last = None
    while time.monotonic() < end:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "Prefix": prefix,
                    "ErrorOutputPrefix": (
                        prefix.rstrip("/") + "-err/!{firehose:error-output-type}/"
                    ),
                    "BufferingHints": dict(_BUFFER),
                    "CompressionFormat": "UNCOMPRESSED",
                    "CloudWatchLoggingOptions": {
                        "Enabled": True,
                        "LogGroupName": log_group,
                        "LogStreamName": _LOG_STREAM,
                    },
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(lambda n=name: _delete_stream_and_wait(firehose, n))
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(5.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}, Prefix={prefix!r}) never succeeded within "
        f"{_CREATE_BUDGET_S}s; last error {last}"
    )


def _delete_stream_and_wait(firehose, name: str, timeout_s: float = 300.0) -> None:
    """Delete the stream and poll every 2 s until it is gone: DeleteDeliveryStream returns while
    the stream is still DELETING, and a still-listed stream is a leak. Raises at the deadline."""
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present {timeout_s}s after DeleteDeliveryStream")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
