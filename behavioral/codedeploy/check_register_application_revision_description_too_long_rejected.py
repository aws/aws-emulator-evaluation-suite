"""register-application-revision-description-too-long-rejected."""
from __future__ import annotations

import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-application-revision-description-too-long-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterApplicationRevision with an over-length description raises
    DescriptionTooLongException and the revision is never actually registered; the exact same
    revision registers fine with a normal-length description."""
    cd = ctx.client("codedeploy")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-cd-app-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    bucket = ctx.unique_name("sim2real-cd-bundle-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))

    key = "bundle.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", "version: 0.0\nos: linux\nfiles: []\n")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    revision = {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"},
    }

    too_long_description = "x" * 4001  # comfortably past any documented real max length
    error = _client_error(
        lambda: cd.register_application_revision(
            applicationName=app_name, description=too_long_description, revision=revision
        )
    )
    assert error == (
        "DescriptionTooLongException",
        "Revision description has a maximum length of 512",
    ), error

    # effect absent: the revision was never actually registered
    get_error = _client_error(
        lambda: cd.get_application_revision(applicationName=app_name, revision=revision)
    )
    assert get_error == (
        "RevisionDoesNotExistException",
        "No application revision found for revision.",
    ), get_error

    # positive control: the exact same revision registers fine with a normal-length description
    cd.register_application_revision(
        applicationName=app_name, description="a short, valid description", revision=revision
    )
    revision_info = cd.get_application_revision(applicationName=app_name, revision=revision)[
        "revisionInfo"
    ]
    assert revision_info["description"] == "a short, valid description"


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
