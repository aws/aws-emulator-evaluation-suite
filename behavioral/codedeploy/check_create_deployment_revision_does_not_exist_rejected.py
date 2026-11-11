"""create-deployment-revision-does-not-exist-rejected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-deployment-revision-does-not-exist-rejected"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApplicationRevision on a never-registered revision fails with
    RevisionDoesNotExistException, while a registered one is returned and listed."""
    cd = ctx.client("codedeploy")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    # Never registered -- the object doesn't even need to exist in S3 for this
    # exception, since CodeDeploy tracks revisions by registration, not by probing S3.
    unregistered_revision = {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": "never/registered.zip", "bundleType": "zip"},
    }
    code, message = _error(
        lambda: cd.get_application_revision(applicationName=app_name, revision=unregistered_revision)
    )
    assert code == "RevisionDoesNotExistException", f"unexpected error code: {code!r}"
    assert message == "No application revision found for revision.", f"unexpected message: {message!r}"

    before = {
        (r["s3Location"]["bucket"], r["s3Location"]["key"])
        for r in cd.list_application_revisions(applicationName=app_name)["revisions"]
    }
    assert (bucket, "never/registered.zip") not in before, (
        f"unregistered revision must not be listed, got {before!r}"
    )

    s3.put_object(Bucket=bucket, Key="real/registered.zip", Body=b"sim2real-codedeploy-revision-body")
    real_revision = {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": "real/registered.zip", "bundleType": "zip"},
    }
    cd.register_application_revision(
        applicationName=app_name, revision=real_revision, description="registered for round-trip"
    )
    got = cd.get_application_revision(applicationName=app_name, revision=real_revision)
    assert got["revision"]["s3Location"]["key"] == "real/registered.zip", (
        f"expected key 'real/registered.zip', got {got['revision']['s3Location']!r}"
    )
    assert got["revisionInfo"]["description"] == "registered for round-trip", (
        f"expected description 'registered for round-trip', got {got['revisionInfo']!r}"
    )

    after = {
        (r["s3Location"]["bucket"], r["s3Location"]["key"])
        for r in cd.list_application_revisions(applicationName=app_name)["revisions"]
    }
    assert (bucket, "real/registered.zip") in after, (
        f"expected registered revision to appear in listing, got {after!r}"
    )
    assert (bucket, "never/registered.zip") not in after, (
        f"never-registered revision must still be absent from listing, got {after!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdbkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

