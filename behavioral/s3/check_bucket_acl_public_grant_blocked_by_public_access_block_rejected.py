"""bucket-acl-public-grant-blocked-by-public-access-block-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-acl-public-grant-blocked-by-public-access-block-rejected"
GROUP = "state-machine"
SERVICES = ["s3"]

_NO_BLOCK = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}


def _has_public_grant(grants) -> bool:
    return any(
        g["Grantee"].get("Type") == "Group"
        and g["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers"
        for g in grants
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With BlockPublicAcls on an ObjectWriter bucket, PutBucketAcl('public-read') is rejected with
    AccessDenied and its exact message and leaves the grants unchanged; after the block is lifted the
    identical call applies the public grant."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-aclblock-")
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    # Allow ACL usage in general...
    s3.put_bucket_ownership_controls(
        Bucket=name, OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]}
    )

    # establish a known baseline: no block at all, regardless of account-level defaults
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=_NO_BLOCK)

    # positive control: absent any block, the public canned ACL this check will later
    # reject is itself accepted -- otherwise "rejected under the block" is
    # indistinguishable from "rejected regardless of the block".
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    control_grants = s3.get_bucket_acl(Bucket=name)["Grants"]
    assert _has_public_grant(control_grants), (
        f"expected a public AllUsers grant with no block in effect, got {control_grants}"
    )
    s3.put_bucket_acl(Bucket=name, ACL="private")  # reset to a clean baseline

    # ...but explicitly block public ACL grants (plus public policy and
    # restrict-public-buckets).
    block = {**_NO_BLOCK, "BlockPublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=block)
    before = s3.get_bucket_acl(Bucket=name)["Grants"]

    code, message = _client_error(lambda: s3.put_bucket_acl(Bucket=name, ACL="public-read"))
    assert code == "AccessDenied", f"expected AccessDenied for public ACL under BlockPublicAcls, got {code}"
    # The message names the caller's own identity, read here rather than pinned.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected = (
        f'User: {caller_arn} is not authorized to perform: s3:PutBucketAcl on resource: '
        f'"arn:aws:s3:::{name}" because public ACLs are prevented by the BlockPublicAcls '
        f'setting in S3 Block Public Access.'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the forbidden effect did not happen: bucket ACL grants are unchanged, still no public grant
    after = s3.get_bucket_acl(Bucket=name)["Grants"]
    assert after == before, f"rejected PutBucketAcl must leave grants unchanged: before={before} after={after}"
    assert not _has_public_grant(after), f"no public grant may appear after the rejected call: {after}"

    # A non-public canned ACL still works fine under the same block configuration.
    s3.put_bucket_acl(Bucket=name, ACL="private")
    got = s3.get_bucket_acl(Bucket=name)
    assert all(
        g["Grantee"].get("URI") != "http://acs.amazonaws.com/groups/global/AllUsers" for g in got["Grants"]
    ), got

    # restore: lift the block, and the identical public-read call now succeeds
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=_NO_BLOCK)
    s3.put_bucket_acl(Bucket=name, ACL="public-read")
    restored_grants = s3.get_bucket_acl(Bucket=name)["Grants"]
    assert _has_public_grant(restored_grants), (
        f"expected the identical PutBucketAcl(public-read) to succeed once the block is "
        f"lifted, got {restored_grants}"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        s3.delete_public_access_block(Bucket=name)
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
