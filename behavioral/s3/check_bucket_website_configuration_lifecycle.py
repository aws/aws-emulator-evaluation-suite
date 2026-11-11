"""bucket-website-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bucket-website-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A fresh bucket has no website config; PutBucketWebsite -> GetBucketWebsite roundtrips
    index/error docs exactly (no stray RedirectAllRequestsTo); DeleteBucketWebsite clears the
    static-site configuration entirely."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-website-")
    _create_bucket(ctx, s3, name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))

    code_before, message_before = _error(lambda: s3.get_bucket_website(Bucket=name))
    assert code_before == "NoSuchWebsiteConfiguration", (
        f"expected NoSuchWebsiteConfiguration on a fresh bucket, got {code_before!r}"
    )
    assert message_before == "The specified bucket does not have a website configuration", message_before

    s3.put_bucket_website(
        Bucket=name,
        WebsiteConfiguration={
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )
    got = s3.get_bucket_website(Bucket=name)
    assert got["IndexDocument"] == {"Suffix": "index.html"}, (
        f"expected IndexDocument {{'Suffix': 'index.html'}}, got {got.get('IndexDocument')!r}"
    )
    assert got["ErrorDocument"] == {"Key": "error.html"}, (
        f"expected ErrorDocument {{'Key': 'error.html'}}, got {got.get('ErrorDocument')!r}"
    )
    assert "RedirectAllRequestsTo" not in got, f"unexpected RedirectAllRequestsTo in {got!r}"

    s3.delete_bucket_website(Bucket=name)

    code_after, message_after = _error(lambda: s3.get_bucket_website(Bucket=name))
    assert code_after == "NoSuchWebsiteConfiguration", (
        f"expected NoSuchWebsiteConfiguration after delete, got {code_after!r}"
    )
    assert message_after == "The specified bucket does not have a website configuration", message_after


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, name: str, **kwargs) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str, bypass_governance: bool = False) -> None:
    from botocore.exceptions import ClientError

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
