"""create-session-express-zone."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-session-express-zone"
GROUP = "state-machine"
SERVICES = ["s3"]

_NO_SUCH_BUCKET = ("NoSuchBucket", 'The specified bucket does not exist.')

# S3 Express One Zone directory buckets are Zonal: the AZ segment is part of the bucket name
# and must be a real AZ ID in the region under test, so these region literals are load-bearing,
# not incidental.
_S3EXPRESS_AZ_BY_REGION = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession issues scoped temporary credentials for a directory bucket; NoSuchBucket otherwise."""
    s3 = ctx.client("s3")
    if not hasattr(s3, "create_session"):
        raise AssertionError("boto3 s3 client lacks create_session (S3 Express API not available)")

    bucket, az = _create_directory_bucket(ctx, s3)

    resp = s3.create_session(Bucket=bucket)
    creds = resp["Credentials"]
    assert creds["AccessKeyId"], "missing AccessKeyId in session credentials"
    assert creds["SecretAccessKey"], "missing SecretAccessKey in session credentials"
    assert creds["SessionToken"], "missing SessionToken in session credentials"
    now = datetime.datetime.now(datetime.timezone.utc)
    assert creds["Expiration"] > now, "session credentials are already expired"
    assert creds["Expiration"] <= now + datetime.timedelta(minutes=6), f"expected a TTL of roughly 5 minutes, got expiration {creds['Expiration']}"

    # The minted session is not just well-shaped, it is genuinely usable: an independent
    # operation (put_object/get_object, not create_session) against the same bucket proves the
    # zone-scoped credentials actually authorize Zonal data-plane calls.
    key = ctx.unique_name("sim2real-s3exp-obj-")
    payload = b"create-session-express-zone-payload"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == payload, f"expected round-tripped payload {payload!r}, got {got!r}"

    # Positive control established above; now break the one precondition: bucket existence.
    # The AZ segment MUST belong to the region under test, otherwise S3 Express endpoint
    # resolution can't even build a resolvable hostname (DNS/connect failure) and we'd never
    # reach the service to observe NoSuchBucket. Reuse the same (region-valid) AZ used above.
    missing = f"{ctx.unique_name('sim2real-s3exp-').lower().rstrip('-')}--{az}--x-s3"
    refusal = _error(lambda: s3.create_session(Bucket=missing))
    assert refusal == _NO_SUCH_BUCKET, f"expected {_NO_SUCH_BUCKET!r}, got {refusal!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A call that SUCCEEDS
    fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_directory_bucket(ctx, s3):
    azs = _S3EXPRESS_AZ_BY_REGION.get(ctx.region)
    if not azs:
        raise AssertionError(f"S3 Express One Zone AZ IDs not known for region {ctx.region}")
    base = ctx.unique_name("sim2real-s3exp-").lower().rstrip("-")
    last_err = None
    for az in azs:
        bucket = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last_err = exc
            continue

        def _cleanup(name=bucket):
            try:
                resp = s3.list_objects_v2(Bucket=name)
                for obj in resp.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                    raise
            try:
                s3.delete_bucket(Bucket=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchBucket":
                    raise

        ctx.on_cleanup(_cleanup)
        return bucket, az
    raise AssertionError(f"could not create an S3 Express directory bucket in {ctx.region}: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
