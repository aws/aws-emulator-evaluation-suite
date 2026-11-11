"""file-extension-overrides-the-compression-suffix-without-changing-the-bytes."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "file-extension-overrides-the-compression-suffix-without-changing-the-bytes"
GROUP = "delivery-format"
SERVICES = ["firehose"]

# Matches the model pattern `^$|\.[0-9a-z!\-_.*'()]+$`: leading period, then only
# lowercase alphanumerics, '-', '.'. Deliberately NOT ending in ".gz", so "the default
# suffix was replaced" and "the default suffix was kept" are distinguishable.
_GOOD_EXT = ".sim2real-fh.gz2"
_BAD_EXT_NO_PERIOD = "nodot"
_BAD_EXT_UPPERCASE = ".UPPER"
_GZIP_MAGIC = b"\x1f\x8b"
_FILE_EXTENSION_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'extendedS3DestinationConfiguration.fileExtension' "
    "failed to satisfy constraint: Member must satisfy regular expression pattern: "
    "^(|\\.[0-9a-z!\\-_.*'()]+)$"
)

# Zero buffering: delivery follows within seconds; the claim does not depend on the interval.
_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 0}
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """FileExtension replaces the default ".gz" key suffix while the bytes stay gzip; extensions
    without a leading period or with uppercase are rejected with ValidationException.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    control_leg = "ext-default"
    treated_leg = "ext-custom"
    # The valid create is the positive control for the two rejections below.
    control = _create_stream(ctx, bucket, role_arn, control_leg, file_extension=None)
    treated = _create_stream(ctx, bucket, role_arn, treated_leg, file_extension=_GOOD_EXT)

    control_desc = _wait_active(ctx, control)
    treated_desc = _wait_active(ctx, treated)

    treated_cfg = treated_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    control_cfg = control_desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert treated_cfg.get("FileExtension") == _GOOD_EXT, (
        f"the treated stream reports FileExtension {treated_cfg.get('FileExtension')!r}, "
        f"expected {_GOOD_EXT!r}"
    )
    assert control_cfg.get("FileExtension", "") in ("", None), (
        f"the control stream reports FileExtension {control_cfg.get('FileExtension')!r}; none "
        f"was supplied, so it must come back absent or empty"
    )
    for leg, cfg in (("control", control_cfg), ("treated", treated_cfg)):
        assert cfg["CompressionFormat"] == "GZIP", (
            f"the {leg} stream reports CompressionFormat {cfg['CompressionFormat']!r}, "
            f"expected GZIP -- both legs must compress for the suffix comparison to be about "
            f"FileExtension alone"
        )

    for bad in (_BAD_EXT_NO_PERIOD, _BAD_EXT_UPPERCASE):
        rejected_name = ctx.unique_name("sim2real-fh-ext-bad-")
        code, message = _error_code(
            lambda n=rejected_name, b=bad: firehose.create_delivery_stream(
                DeliveryStreamName=n,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                    "Prefix": "rejected/",
                    "BufferingHints": dict(_BUFFER),
                    "CompressionFormat": "GZIP",
                    "FileExtension": b,
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            ),
            what=f"CreateDeliveryStream with FileExtension={bad!r}",
        )
        # botocore does not enforce the pattern client side; the service rejects it with
        # ValidationException, not the modeled InvalidArgumentException.
        assert code == "ValidationException", (
            f"CreateDeliveryStream with FileExtension={bad!r} was refused with error code "
            f"{code!r} (message {message!r}); expected ValidationException. The allowed "
            f"form is a leading period followed by [0-9a-z!-_.*'()] only"
        )
        # The pattern-validation message, which also separates "the extension is
        # malformed" from "the role is still propagating" (same code, other message).
        assert message == _FILE_EXTENSION_PATTERN_MESSAGE, (
            f"CreateDeliveryStream with FileExtension={bad!r} was refused with message "
            f"{message!r}; expected {_FILE_EXTENSION_PATTERN_MESSAGE!r}"
        )
        assert rejected_name not in _all_stream_names(ctx), (
            f"the refused stream {rejected_name!r} appears in ListDeliveryStreams; a rejected "
            f"CreateDeliveryStream must leave nothing behind"
        )

    payload = f"{CHECK}|{ctx.unique_name('rec-')}".encode()
    firehose.put_record(DeliveryStreamName=control, Record={"Data": payload})
    firehose.put_record(DeliveryStreamName=treated, Record={"Data": payload})

    control_key = _wait_for_one_object(ctx, bucket, control_leg + "/")
    treated_key = _wait_for_one_object(ctx, bucket, treated_leg + "/")

    assert control_key.endswith(".gz"), (
        f"with CompressionFormat=GZIP and no FileExtension the delivered key must carry the "
        f"default '.gz' suffix; got {control_key!r}"
    )
    assert treated_key.endswith(_GOOD_EXT), (
        f"with FileExtension={_GOOD_EXT!r} the delivered key must end in that extension; got "
        f"{treated_key!r}"
    )
    assert not treated_key.endswith(".gz"), (
        f"the treated key {treated_key!r} still ends in '.gz'; FileExtension must REPLACE the "
        f"suffix the compression feature would add, not be appended in front of it"
    )

    # FileExtension is cosmetic: the bytes stay gzip.
    for leg, key in (("control", control_key), ("treated", treated_key)):
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert body[:2] == _GZIP_MAGIC, (
            f"the {leg} leg's object s3://{bucket}/{key} does not start with the gzip magic; "
            f"first bytes were {body[:2]!r}. CompressionFormat=GZIP must compress the "
            f"delivered bytes regardless of what the key is named"
        )
        plain = gzip.decompress(body)
        assert plain.strip(b"\n") == payload, (
            f"the {leg} leg's object gunzips to {plain[:200]!r}, expected exactly the record "
            f"that was put ({payload!r})"
        )


def _error_code(call, *, what: str) -> tuple[str, str]:
    """Return (code, message) for a call that must fail; raises on unexpected success."""
    try:
        call()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message", ""),
        )
    raise AssertionError(f"{what} was expected to be refused but succeeded")


def _all_stream_names(ctx) -> list[str]:
    firehose = ctx.client("firehose")
    names: list[str] = []
    start = None
    while True:
        kwargs = {"Limit": 100}
        if start:
            kwargs["ExclusiveStartDeliveryStreamName"] = start
        resp = firehose.list_delivery_streams(**kwargs)
        page = resp["DeliveryStreamNames"]
        names.extend(page)
        if not resp["HasMoreDeliveryStreams"]:
            return names
        assert page, (
            "ListDeliveryStreams reported HasMoreDeliveryStreams with an empty page, which "
            "would loop forever"
        )
        start = page[-1]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-ext-")
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
    """Bounded at 40 s so the remaining cleanups fit the shared 60 s cleanup budget."""
    s3 = ctx.client("s3")
    end = time.monotonic() + 40.0
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
            time.sleep(4.0)
    raise AssertionError(f"bucket {bucket!r} could not be emptied and deleted within 40s")


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-ext-role-")
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


def _create_stream(ctx, bucket: str, role_arn: str, leg: str, *, file_extension) -> str:
    """Create the stream, retrying InvalidArgumentException while the new role propagates.
    Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-fh-{leg}-")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": f"{leg}/",
        "ErrorOutputPrefix": f"{leg}-err/!{{firehose:error-output-type}}/",
        "BufferingHints": dict(_BUFFER),
        "CompressionFormat": "GZIP",
    }
    if file_extension is not None:
        dest["FileExtension"] = file_extension

    end = time.monotonic() + _capped(ctx, _CREATE_BUDGET_S)
    last = None
    while time.monotonic() < end:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(
                lambda n=name: firehose.delete_delivery_stream(
                    DeliveryStreamName=n, AllowForceDelete=True
                )
            )
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(2.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}) never succeeded within {_CREATE_BUDGET_S}s; last "
        f"error {last}"
    )


def _wait_active(ctx, name: str) -> dict:
    firehose = ctx.client("firehose")
    end = time.monotonic() + _capped(ctx, _ACTIVE_BUDGET_S)
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
        time.sleep(2.0)
    raise AssertionError(
        f"delivery stream {name!r} never became ACTIVE within {_ACTIVE_BUDGET_S}s (last "
        f"status {status!r})"
    )


def _capped(ctx, budget_s: float) -> float:
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, left)


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


def _wait_for_one_object(ctx, bucket: str, prefix: str) -> str:
    """Bounded poll for exactly one delivered object; raises on timeout."""
    end = time.monotonic() + _capped(ctx, _DELIVERY_BUDGET_S)
    keys: list[str] = []
    while time.monotonic() < end:
        keys = _all_keys(ctx, bucket, prefix)
        if keys:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert len(keys) == 1, (
        f"DATAPLANE_UNIMPLEMENTED?: expected exactly 1 delivered object under "
        f"s3://{bucket}/{prefix} within {_DELIVERY_BUDGET_S}s, found {len(keys)}: {keys!r}"
    )
    return keys[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
