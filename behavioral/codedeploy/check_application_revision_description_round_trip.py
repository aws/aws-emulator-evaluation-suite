"""application-revision-description-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-revision-description-round-trip"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode revision description written via RegisterApplicationRevision comes back
    byte-identical from GetApplicationRevision."""
    cd = ctx.client("codedeploy")
    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "env", "Value": "test"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    description = "R\u00e9sum\u00e9 caf\u00e9 \u9b3c \U0001F680 -- unicode deploy notes \u2603"
    revision = {
        "revisionType": "S3",
        "s3Location": {
            "bucket": ctx.unique_name("sim2real-cdbucket-").lower(),
            "key": "releases/app.zip",
            "bundleType": "zip",
        },
    }
    cd.register_application_revision(
        applicationName=app_name, revision=revision, description=description
    )

    resp = cd.get_application_revision(applicationName=app_name, revision=revision)
    got_description = resp["revisionInfo"]["description"]
    assert got_description == description, f"expected description {description!r}, got {got_description!r}"
    got_app_name = resp["applicationName"]
    assert got_app_name == app_name, f"expected applicationName {app_name!r}, got {got_app_name!r}"
    got_bucket = resp["revision"]["s3Location"]["bucket"]
    assert got_bucket == revision["s3Location"]["bucket"], f"expected bucket {revision['s3Location']['bucket']!r}, got {got_bucket!r}"
    got_key = resp["revision"]["s3Location"]["key"]
    assert got_key == revision["s3Location"]["key"], f"expected key {revision['s3Location']['key']!r}, got {got_key!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
