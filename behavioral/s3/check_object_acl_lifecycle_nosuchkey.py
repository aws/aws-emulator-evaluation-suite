"""object-acl-lifecycle-nosuchkey."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-acl-lifecycle-nosuchkey"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectAcl/GetObjectAcl succeed and roundtrip a custom grant while the
    object exists; after DeleteObject, GetObjectAcl transitions to NoSuchKey."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-oacl-")
    key = "object-acl-test.txt"
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    # Object ACLs need ACLs enabled on the bucket (BucketOwnerEnforced disables them).
    s3.put_bucket_ownership_controls(
        Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    s3.put_object(Bucket=name, Key=key, Body=b"acl-lifecycle-payload")

    owner = s3.get_object_acl(Bucket=name, Key=key)["Owner"]
    s3.put_object_acl(
        Bucket=name,
        Key=key,
        AccessControlPolicy={
            "Owner": owner,
            "Grants": [
                {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                    "Permission": "READ_ACP",
                },
            ],
        },
    )

    got = s3.get_object_acl(Bucket=name, Key=key)
    log_delivery = [
        g
        for g in got["Grants"]
        if g["Permission"] == "READ_ACP"
        and g["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/s3/LogDelivery"
    ]
    assert len(log_delivery) == 1, got["Grants"]

    s3.delete_object(Bucket=name, Key=key)

    code, message = _error(lambda: s3.get_object_acl(Bucket=name, Key=key))
    assert code == "NoSuchKey", code
    assert message == "The specified key does not exist.", f"unexpected NoSuchKey message: {message!r}"

    # Gone means unusable too: a mutation against the same dead key fails identically.
    put_code, put_message = _error(lambda: s3.put_object_acl(Bucket=name, Key=key, ACL="private"))
    assert put_code == "NoSuchKey", put_code
    assert put_message == "The specified key does not exist.", f"unexpected NoSuchKey message: {put_message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
