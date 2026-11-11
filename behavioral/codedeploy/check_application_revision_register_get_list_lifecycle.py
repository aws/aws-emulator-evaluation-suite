"""application-revision-register-get-list-lifecycle."""
from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags

CHECK = "application-revision-register-get-list-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterApplicationRevision makes a revision retrievable via GetApplicationRevision
    (with the registered description) and it appears exactly once in
    ListApplicationRevisions filtered to the backing S3 bucket."""
    codedeploy = ctx.client("codedeploy")
    s3 = ctx.client("s3")

    bucket = _create_revision_bucket(ctx)
    key = "revisions/app.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_build_minimal_appspec_zip())

    app_name = ctx.unique_name("sim2real-cd-app-")
    codedeploy.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    revision = {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip"},
    }
    description = "sim2real behavioral revision"
    codedeploy.register_application_revision(
        applicationName=app_name, revision=revision, description=description
    )

    got = codedeploy.get_application_revision(applicationName=app_name, revision=revision)
    assert got["applicationName"] == app_name, (
        f"expected GetApplicationRevision to echo the application name {app_name!r}, got {got['applicationName']!r}"
    )
    assert got["revisionInfo"]["description"] == description, (
        f"expected the registered description {description!r}, got {got['revisionInfo'].get('description')!r}"
    )
    assert "registerTime" in got["revisionInfo"], (
        f"expected revisionInfo to carry a registerTime, got keys {sorted(got['revisionInfo'])}"
    )

    listed = codedeploy.list_application_revisions(applicationName=app_name, s3Bucket=bucket)[
        "revisions"
    ]
    matched = [
        r
        for r in listed
        if r.get("s3Location", {}).get("key") == key
        and r.get("s3Location", {}).get("bucket") == bucket
    ]
    assert len(matched) == 1, f"expected the registered revision to appear exactly once, got {listed}"


def _create_revision_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cd-rev-").lower()
    kwargs = {}
    # us-east-1 is CreateBucket's implicit default; passing a LocationConstraint for it is rejected.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _build_minimal_appspec_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "appspec.yml",
            "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp\n",
        )
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
