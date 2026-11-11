"""directory-buckets-listing."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "directory-buckets-listing"
GROUP = "state-machine"
SERVICES = ["s3"]

# Fixed S3 Express One Zone AZ IDs per region — a real AWS constant (not an
# account-specific quota), required to construct a valid directory-bucket name.
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDirectoryBuckets returns only S3 Express directory buckets, disjoint from ListBuckets."""
    s3 = ctx.client("s3")
    if not hasattr(s3, "list_directory_buckets"):
        raise AssertionError(
            "boto3 s3 client lacks list_directory_buckets (S3 Express API not available)"
        )

    dirbucket = _create_directory_bucket(ctx, s3)
    regular = _new_bucket(ctx, s3)

    dir_listed = s3.list_directory_buckets()
    dir_names = [b["Name"] for b in dir_listed.get("Buckets", [])]
    assert dirbucket in dir_names, (
        f"expected directory bucket {dirbucket} in {dir_names}"
    )
    assert regular not in dir_names, (
        f"regular bucket {regular} unexpectedly in ListDirectoryBuckets: {dir_names}"
    )

    reg_listed = s3.list_buckets()
    reg_names = [b["Name"] for b in reg_listed.get("Buckets", [])]
    assert regular in reg_names, f"expected regular bucket {regular} in {reg_names}"
    assert dirbucket not in reg_names, (
        f"directory bucket {dirbucket} unexpectedly in ListBuckets: {reg_names}"
    )


def _create_directory_bucket(ctx, s3):
    azs = _S3EXPRESS_AZ_BY_REGION.get(ctx.region)
    if not azs:
        raise AssertionError(
            f"S3 Express One Zone AZ IDs not known for region {ctx.region}"
        )
    base = ctx.unique_name("sim2real-s3exp-").lower().rstrip("-")
    last_err = None
    for az in azs:
        bucket = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {
                        "DataRedundancy": "SingleAvailabilityZone",
                        "Type": "Directory",
                    },
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
        return bucket
    raise AssertionError(
        f"could not create an S3 Express directory bucket in {ctx.region}: {last_err}"
    )


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-s3-behav-").lower()
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=name)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
