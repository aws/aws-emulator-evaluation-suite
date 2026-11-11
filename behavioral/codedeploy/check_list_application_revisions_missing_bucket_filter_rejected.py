"""list-application-revisions-missing-bucket-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-application-revisions-missing-bucket-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListApplicationRevisions with an s3KeyPrefix filter but no s3Bucket raises
    BucketNameFilterRequiredException (a key-prefix filter narrows the search within a bucket,
    so a bucket must be named), while the identical call with an s3Bucket supplied succeeds."""
    cd = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real", "Value": app_name}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    code, message = _error(
        lambda: cd.list_application_revisions(applicationName=app_name, s3KeyPrefix="builds/")
    )
    assert code == "BucketNameFilterRequiredException", f"got {code!r}"
    assert message == "S3 object key prefix filter specified without specifying bucket name", message

    # positive control: supplying the required bucket filter alongside the same s3KeyPrefix
    # value succeeds (the app has no registered revisions, so the list is simply empty)
    bucket = f"aws-codedeploy-{ctx.region}"
    resp = cd.list_application_revisions(
        applicationName=app_name, s3KeyPrefix="builds/", s3Bucket=bucket
    )
    assert resp["revisions"] == [], f"expected no revisions, got {resp['revisions']!r}"


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
