"""bucket-acl-put-get-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-acl-put-get-roundtrip"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketAcl sets an explicit grant set (owner FULL_CONTROL plus a
    LogDelivery group grant) and GetBucketAcl returns exactly that grantee/permission
    set back."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-bacl-")
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    # ACLs are unusable on a bucket with BucketOwnerEnforced ownership (today's
    # default); relax it so PutBucketAcl is actually honored.
    s3.put_bucket_ownership_controls(
        Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    owner = s3.get_bucket_acl(Bucket=name)["Owner"]

    s3.put_bucket_acl(
        Bucket=name,
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

    got = s3.get_bucket_acl(Bucket=name)
    assert got["Owner"]["ID"] == owner["ID"], got

    grants = got["Grants"]
    assert len(grants) == 2, grants  # PutBucketAcl replaces the grant set; nothing else survives it

    full_control = [g for g in grants if g["Permission"] == "FULL_CONTROL"]
    assert any(g["Grantee"].get("ID") == owner["ID"] for g in full_control), grants

    log_delivery = [
        g
        for g in grants
        if g["Permission"] == "READ_ACP"
        and g["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/s3/LogDelivery"
    ]
    assert len(log_delivery) == 1, grants


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
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.head_bucket(Bucket=name)
    except ClientError as e:
        if e.response["ResponseMetadata"]["HTTPStatusCode"] != 404:
            raise
    else:
        raise AssertionError(f"bucket {name} still exists after delete_bucket")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
