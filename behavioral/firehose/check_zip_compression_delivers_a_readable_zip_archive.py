"""zip-compression-delivers-a-readable-zip-archive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "zip-compression-delivers-a-readable-zip-archive"
GROUP = "delivery-format"
SERVICES = ["firehose"]

_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"
_RECORD_COUNT = 4

_BUFFER = {"SizeInMBs": 1, "IntervalInSeconds": 60}
_DELIVERY_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_ACTIVE_BUDGET_S = 180.0
_CREATE_BUDGET_S = 180.0


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CompressionFormat=ZIP delivers a valid PKZIP archive whose extracted members equal the
    bytes an UNCOMPRESSED control stream delivers for the same records.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"expected GetCallerIdentity to report a numeric account id, got {account!r}"
    )

    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    control_leg = "zip-plain"
    treated_leg = "zip-zip"
    # The UNCOMPRESSED leg supplies the expected bytes and proves the pipeline delivers at all.
    control = _create_stream(ctx, bucket, role_arn, control_leg, compression="UNCOMPRESSED")
    treated = _create_stream(ctx, bucket, role_arn, treated_leg, compression="ZIP")

    control_desc = _wait_active(ctx, control)
    treated_desc = _wait_active(ctx, treated)

    assert (
        treated_desc["Destinations"][0]["ExtendedS3DestinationDescription"]["CompressionFormat"]
        == "ZIP"
    ), (
        f"the treated stream reports CompressionFormat "
        f"{treated_desc['Destinations'][0]['ExtendedS3DestinationDescription']['CompressionFormat']!r}"
        f", expected ZIP"
    )
    assert (
        control_desc["Destinations"][0]["ExtendedS3DestinationDescription"]["CompressionFormat"]
        == "UNCOMPRESSED"
    ), (
        f"the control stream reports CompressionFormat "
        f"{control_desc['Destinations'][0]['ExtendedS3DestinationDescription']['CompressionFormat']!r}"
        f", expected UNCOMPRESSED -- it must not compress, or it cannot supply the expected bytes"
    )

    # Records are newline-terminated by this check so the concatenation the two legs see is
    # unambiguous; Firehose itself appends no delimiter without a processor.
    nonce = ctx.unique_name("z-")
    records = [
        {"Data": f"{nonce}-record-{i:02d}-{'x' * (i * 7)}\n".encode()}
        for i in range(_RECORD_COUNT)
    ]

    control_resp = firehose.put_record_batch(DeliveryStreamName=control, Records=records)
    treated_resp = firehose.put_record_batch(DeliveryStreamName=treated, Records=records)
    for leg, resp in (("control", control_resp), ("treated", treated_resp)):
        assert resp["FailedPutCount"] == 0, (
            f"PutRecordBatch on the {leg} leg reported FailedPutCount "
            f"{resp['FailedPutCount']}, expected 0. Response: "
            f"{resp['RequestResponses']!r}"
        )

    control_keys = _wait_for_objects(ctx, bucket, control_leg + "/")
    treated_keys = _wait_for_objects(ctx, bucket, treated_leg + "/")

    control_body = b"".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in control_keys
    )
    treated_body = b"".join(
        s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in treated_keys
    )

    # The control leg really is plain, otherwise it cannot serve as the expected value.
    assert control_body.count(nonce.encode()) == _RECORD_COUNT, (
        f"the UNCOMPRESSED control leg's {len(control_keys)} object(s) contain "
        f"{control_body.count(nonce.encode())} occurrences of the run nonce {nonce!r}, "
        f"expected {_RECORD_COUNT}. Body begins {control_body[:200]!r}"
    )

    # Not plain and not gzip, so the archive assertions below grade ZIP specifically.
    assert nonce.encode() not in treated_body, (
        f"the ZIP leg's delivered bytes contain the plaintext nonce {nonce!r}; "
        f"CompressionFormat=ZIP was configured and echoed back but the bytes were written "
        f"uncompressed. Body begins {treated_body[:200]!r}"
    )
    assert treated_body[:2] != _GZIP_MAGIC, (
        f"the ZIP leg's delivered bytes start with the gzip magic {treated_body[:2]!r}; "
        f"CompressionFormat=ZIP must not produce gzip"
    )

    assert treated_body[:4] == _ZIP_MAGIC, (
        f"the ZIP leg's delivered bytes start with {treated_body[:4]!r}, expected the PKZIP "
        f"local-file-header signature {_ZIP_MAGIC!r}"
    )
    assert zipfile.is_zipfile(io.BytesIO(treated_body)), (
        f"the ZIP leg's {len(treated_body)} delivered bytes carry the PKZIP signature but "
        f"zipfile.is_zipfile rejects them -- the central directory or the end-of-archive "
        f"record is missing or corrupt"
    )

    with zipfile.ZipFile(io.BytesIO(treated_body)) as archive:
        names = archive.namelist()
        assert names, (
            f"the ZIP leg's archive opened but holds no members; the {_RECORD_COUNT} records "
            f"put to it must be inside it"
        )
        extracted = b"".join(archive.read(n) for n in names)

    assert extracted == control_body, (
        f"the ZIP leg's archive decompresses to {len(extracted)} bytes that differ from the "
        f"UNCOMPRESSED control leg's {len(control_body)} bytes for the same "
        f"{_RECORD_COUNT} records. Archive members {names!r}. Extracted begins "
        f"{extracted[:150]!r}; control begins {control_body[:150]!r}"
    )

    for leg in (control_leg, treated_leg):
        stray = _all_keys(ctx, bucket, leg + "-err/")
        assert stray == [], (
            f"leg {leg!r} wrote {len(stray)} objects under its ErrorOutputPrefix: {stray!r}. "
            f"Nothing in this check should fail delivery"
        )




def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-zip-")
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
    """Bounded at 40 s because all of a check's cleanups share a 60 s budget."""
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
    name = ctx.unique_name("sim2real-fh-zip-role-")
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


def _create_stream(ctx, bucket: str, role_arn: str, leg: str, *, compression: str) -> str:
    """Bounded retry past the transient InvalidArgumentException a freshly created,
    eventually consistent delivery role produces. Raises on exhaustion."""
    firehose = ctx.client("firehose")
    name = ctx.unique_name(f"sim2real-fh-{leg}-")
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
                    "Prefix": f"{leg}/",
                    "ErrorOutputPrefix": f"{leg}-err/!{{firehose:error-output-type}}/",
                    "BufferingHints": dict(_BUFFER),
                    "CompressionFormat": compression,
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(
                lambda n=name: _delete_stream_and_wait(firehose, n, AllowForceDelete=True)
            )
            return name
        except ClientError as err:
            last = err
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            time.sleep(5.0)
    raise AssertionError(
        f"CreateDeliveryStream({name!r}, CompressionFormat={compression!r}) never succeeded "
        f"within {_CREATE_BUDGET_S}s; last error {last}"
    )


def _delete_stream_and_wait(firehose, name: str, timeout_s: float = 300.0, **delete_kwargs) -> None:
    """Delete the delivery stream and poll until it is gone: it keeps listing while DELETING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.delete_delivery_stream(DeliveryStreamName=name, **delete_kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"delivery stream {name!r} still exists {timeout_s:.0f}s after DeleteDeliveryStream"
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


def _wait_for_objects(ctx, bucket: str, prefix: str) -> list[str]:
    """Bounded poll for at least one delivered object. Raises. The wait is for a time-based
    buffer flush (IntervalInSeconds=60) that cannot be hurried."""
    left = ctx.time_left()
    end = time.monotonic() + (
        _DELIVERY_BUDGET_S if left is None else max(1.0, min(_DELIVERY_BUDGET_S, left - 5.0))
    )
    keys: list[str] = []
    while time.monotonic() < end:
        keys = _all_keys(ctx, bucket, prefix)
        if keys:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert keys, (
        f"DATAPLANE_UNIMPLEMENTED?: nothing was delivered under s3://{bucket}/{prefix} within "
        f"{_DELIVERY_BUDGET_S}s. {_RECORD_COUNT} records were put with BufferingHints "
        f"{_BUFFER!r}, so a flush is due"
    )
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
