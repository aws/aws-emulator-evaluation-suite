"""public-access-block-blocks-public-acl."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "public-access-block-blocks-public-acl"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With BlockPublicAcls=True, PutBucketAcl('public-read') is rejected with AccessDenied and its exact
    message and leaves the ACL unchanged, a private ACL still applies, and after the block is lifted the
    public-read call succeeds."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-pab-")
    _create_bucket(
        ctx,
        s3,
        bucket,
        ObjectOwnership="ObjectWriter",  # ACLs must be enabled to isolate the PublicAccessBlock effect
    )

    # establish a known baseline: no block at all, regardless of account-level defaults
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=_NO_BLOCK)

    # positive control: absent any block, the public canned ACL this check will later reject
    # is itself accepted — otherwise "rejected under the block" is indistinguishable from
    # "rejected regardless of the block".
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    control_grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert _has_public_grant(control_grants), (
        f"expected a public AllUsers grant with no block in effect, got {control_grants}"
    )
    s3.put_bucket_acl(Bucket=bucket, ACL="private")  # reset to a clean baseline

    # break exactly one thing
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={**_NO_BLOCK, "BlockPublicAcls": True},
    )
    before = s3.get_bucket_acl(Bucket=bucket)["Grants"]

    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    err = _error(lambda: s3.put_bucket_acl(Bucket=bucket, ACL="public-read"))
    assert err == ("AccessDenied", (
        f"User: {caller_arn} is not authorized to perform: s3:PutBucketAcl on resource: "
        f"\"arn:aws:s3:::{bucket}\" because public ACLs are prevented by the BlockPublicAcls "
        f"setting in S3 Block Public Access."
    )), (
        f"expected AccessDenied for public ACL under BlockPublicAcls, got {err}"
    )

    # the forbidden effect did not happen: bucket ACL grants are unchanged, still no public grant
    after = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert after == before, f"rejected PutBucketAcl must leave grants unchanged: before={before} after={after}"
    assert not _has_public_grant(after), f"no public grant may appear after the rejected call: {after}"

    # a private (non-public) canned ACL is still accepted under the same block
    s3.put_bucket_acl(Bucket=bucket, ACL="private")
    private_grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert len(private_grants) == 1 and private_grants[0]["Permission"] == "FULL_CONTROL", private_grants

    # restore: lift the block, and the identical public-read call now succeeds
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=_NO_BLOCK)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    restored_grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    assert _has_public_grant(restored_grants), (
        f"expected the identical PutBucketAcl(public-read) to succeed once BlockPublicAcls is "
        f"lifted, got {restored_grants}"
    )


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
