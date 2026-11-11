"""bucket-ownership-controls-invalid-value-rejected."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "bucket-ownership-controls-invalid-value-rejected"
GROUP = 'acls_policies'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketOwnershipControls with an ObjectOwnership value outside the enum is rejected with
    MalformedXML and its exact message, and the BucketOwnerPreferred rule set by the valid control call
    stays in place."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    rules = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
    assert rules[0]["ObjectOwnership"] == "BucketOwnerPreferred", (
        f"positive control did not take effect: {rules!r}"
    )

    code, message = _error(
        lambda: s3.put_bucket_ownership_controls(
            Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "NotARealValue"}]}
        )
    )
    assert code == "MalformedXML", (
        f"expected the specific rejection code for an invalid ObjectOwnership value, got {code!r}"
    )
    assert message == "The XML you provided was not well-formed or did not validate against our published schema", message

    after = s3.get_bucket_ownership_controls(Bucket=bucket)["OwnershipControls"]["Rules"]
    assert after[0]["ObjectOwnership"] == "BucketOwnerPreferred", (
        f"the invalid value must not take effect: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
