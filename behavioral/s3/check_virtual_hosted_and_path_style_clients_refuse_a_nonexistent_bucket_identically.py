"""virtual-hosted-and-path-style-clients-refuse-a-nonexistent-bucket-identically."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "virtual-hosted-and-path-style-clients-refuse-a-nonexistent-bucket-identically"
GROUP = "addressing"
SERVICES = ["s3"]

KEY = "cross-addr/missing.bin"


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; FAILS on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message") or "",
        )
    raise AssertionError("the call succeeded; expected a refusal")


def _refusal(got, what):
    """(code, message) of an ``_error`` result, after grading its HTTP 4xx status."""
    code, status, message = got
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: answered HTTP {status!r}, expected 4xx"
    return code, message


def _empty_and_delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject and HeadBucket on a bucket that does not exist are refused NoSuchBucket with the
    same code and message whether addressed virtual-hosted or path-style, while a bucket the check
    created answers both addressing forms with 200.
    """
    plain = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    plain.create_bucket(**create)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(plain, bucket))

    missing = ctx.unique_name("sim2real-behav-bkt-absent-")
    vclient = ctx.client("s3", config=Config(s3={"addressing_style": "virtual"}, retries={"max_attempts": 1}))
    pclient = ctx.client("s3", config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))

    no_bucket = ("NoSuchBucket", "The specified bucket does not exist")
    head_not_found = ("404", "Not Found")
    for client, label in ((vclient, "virtual-hosted"), (pclient, "path-style")):
        got = _refusal(_error(lambda c=client: c.get_object(Bucket=missing, Key=KEY)), f"{label} GetObject on an absent bucket")
        assert got == no_bucket, f"{label} GetObject on an absent bucket: expected {no_bucket}, got {got!r}"
        got = _refusal(_error(lambda c=client: c.head_bucket(Bucket=missing)), f"{label} HeadBucket on an absent bucket")
        assert got == head_not_found, (
            f"{label} HeadBucket on an absent bucket: expected {head_not_found}, got {got!r}"
        )

        # positive control: the same calls against the bucket the check created succeed
        head = client.head_bucket(Bucket=bucket)
        assert head["ResponseMetadata"]["HTTPStatusCode"] == 200, (
            f"{label} HeadBucket on the existing bucket answered {head['ResponseMetadata']}"
        )
        listed = client.list_objects_v2(Bucket=bucket).get("Contents", [])
        assert listed == [], f"{label} ListObjectsV2 on the fresh existing bucket listed {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
