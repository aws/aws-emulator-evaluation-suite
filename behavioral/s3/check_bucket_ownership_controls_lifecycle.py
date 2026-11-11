"""bucket-ownership-controls-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-ownership-controls-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketOwnershipControls(ObjectWriter) is reflected by Get, and after
    DeleteBucketOwnershipControls Get raises OwnershipControlsNotFoundError with its exact message: the
    control is removed, not reset to a default."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ownctl-")
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    s3.put_bucket_ownership_controls(
        Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
    )
    got = s3.get_bucket_ownership_controls(Bucket=name)
    assert got["OwnershipControls"]["Rules"][0]["ObjectOwnership"] == "ObjectWriter", got

    s3.delete_bucket_ownership_controls(Bucket=name)

    try:
        after = s3.get_bucket_ownership_controls(Bucket=name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "OwnershipControlsNotFoundError", (
            f"expected OwnershipControlsNotFoundError after delete, got {code}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "The bucket ownership controls were not found", message
    else:
        raise AssertionError(
            f"expected OwnershipControlsNotFoundError after delete, got a 200: {after}"
        )


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if to_delete:
                kwargs = {"Bucket": name, "Delete": {"Objects": to_delete}}
                if bypass_governance:
                    kwargs["BypassGovernanceRetention"] = True
                failed = s3.delete_objects(**kwargs).get("Errors")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
