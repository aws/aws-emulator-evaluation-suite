"""bucket-acl-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bucket-acl-roundtrip"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Bucket ACL grants set via PutBucketAcl exactly replace the prior grant set and are
    reflected precisely by GetBucketAcl."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bacl-")
    _create_bucket(ctx, s3, bucket, ObjectOwnership="BucketOwnerPreferred")

    owner = s3.get_bucket_acl(Bucket=bucket)["Owner"]
    grants = [
        {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
        {
            "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
            "Permission": "READ_ACP",
        },
    ]
    s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Owner": owner, "Grants": grants})

    got = s3.get_bucket_acl(Bucket=bucket)
    assert got["Owner"]["ID"] == owner["ID"], (owner["ID"], got["Owner"])
    got_pairs = {(g["Grantee"].get("ID") or g["Grantee"].get("URI"), g["Permission"]) for g in got["Grants"]}
    expected_pairs = {(owner["ID"], "FULL_CONTROL"), ("http://acs.amazonaws.com/groups/s3/LogDelivery", "READ_ACP")}
    assert got_pairs == expected_pairs, got_pairs

    # Replacing the ACL with a strictly smaller grant set drops the previous grant entirely
    # (PutBucketAcl replaces, it does not merge).
    s3.put_bucket_acl(
        Bucket=bucket,
        AccessControlPolicy={
            "Owner": owner,
            "Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"}],
        },
    )
    got2 = s3.get_bucket_acl(Bucket=bucket)
    assert len(got2["Grants"]) == 1, got2["Grants"]
    assert got2["Grants"][0]["Permission"] == "FULL_CONTROL", got2["Grants"][0]


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    # us-east-1 is CreateBucket's implicit default region; passing a LocationConstraint for it is rejected.
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))


def _empty_and_delete_bucket(ctx, s3, name):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
