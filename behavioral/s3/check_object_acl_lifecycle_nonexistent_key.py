"""object-acl-lifecycle-nonexistent-key."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "object-acl-lifecycle-nonexistent-key"
GROUP = "state-machine"
SERVICES = ["s3"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectAcl/GetObjectAcl round-trip exactly for an existing key, and GetObjectAcl on a
    key that was never written returns NoSuchKey."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-oacl-")
    _create_bucket(ctx, s3, bucket, ObjectOwnership="BucketOwnerPreferred")

    key = "obj.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello-acl")

    owner = s3.get_object_acl(Bucket=bucket, Key=key)["Owner"]
    grants = [
        {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
        {
            "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
            "Permission": "READ",
        },
    ]
    s3.put_object_acl(Bucket=bucket, Key=key, AccessControlPolicy={"Owner": owner, "Grants": grants})

    got = s3.get_object_acl(Bucket=bucket, Key=key)
    got_pairs = {(g["Grantee"].get("ID") or g["Grantee"].get("URI"), g["Permission"]) for g in got["Grants"]}
    expected_pairs = {(owner["ID"], "FULL_CONTROL"), ("http://acs.amazonaws.com/groups/s3/LogDelivery", "READ")}
    assert got_pairs == expected_pairs, f"expected grants {expected_pairs}, got {got_pairs}"

    # Negative: a key that was never created has no ACL to retrieve.
    code, message = _error(lambda: s3.get_object_acl(Bucket=bucket, Key="never-written.txt"))
    assert code == "NoSuchKey", f"expected NoSuchKey, got {code}"
    assert message == "The specified key does not exist.", f"unexpected NoSuchKey message: {message!r}"


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    # us-east-1 is CreateBucket's implicit default; passing a LocationConstraint for it is rejected.
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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
