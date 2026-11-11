"""application-revision-description-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-revision-description-unicode-round-trip"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RegisterApplicationRevision description containing unicode across several
    scripts, combining marks and emoji, plus a long body, comes back byte-identical
    via GetApplicationRevision."""
    codedeploy = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    codedeploy.create_application(
        applicationName=app_name,
        computePlatform="Server",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: codedeploy.delete_application(applicationName=app_name))

    revision = _upload_revision_bundle(ctx)

    # Uses proper single-codepoint \U escapes for the emoji (not raw surrogate-pair
    # escapes) so the string is valid, well-formed UTF-8 end to end — lone surrogates
    # are not valid Unicode scalar values and would not round-trip reliably over any
    # UTF-8-based wire protocol on real AWS.
    description = (
        "Sim2Real \u00fcn\u00edc\u00f8d\u00e9 \u6d4b\u8bd5 \u30c6\u30b9\u30c8 "
        "\u0442\u0435\u0441\u0442 \u0627\u062e\u062a\u0628\u0627\u0631 "
        "\U0001F680\U0001F525\u2705 caf\u00e9 na\u00efve r\u00e9sum\u00e9 "
    ) * 3
    assert len(description) > 100, f"test fixture too short to be a meaningful round-trip: {len(description)} chars"

    codedeploy.register_application_revision(applicationName=app_name, description=description, revision=revision)

    got = codedeploy.get_application_revision(applicationName=app_name, revision=revision)
    assert got["applicationName"] == app_name, f"expected applicationName {app_name!r}, got {got['applicationName']!r}"
    assert got["revisionInfo"]["description"] == description, "description was not byte-identical on round-trip"
    assert got["revision"]["s3Location"]["bucket"] == revision["s3Location"]["bucket"], (
        f"expected bucket {revision['s3Location']['bucket']!r}, got {got['revision']['s3Location']['bucket']!r}"
    )
    assert got["revision"]["s3Location"]["key"] == revision["s3Location"]["key"], (
        f"expected key {revision['s3Location']['key']!r}, got {got['revision']['s3Location']['key']!r}"
    )


def _upload_revision_bundle(ctx) -> dict:
    import io
    import zipfile

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cdrev-").lower()
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 (its own default).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        s3.delete_object(Bucket=bucket, Key="revision.zip")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    appspec = "version: 0.0\nos: linux\nfiles:\n  - source: /\n    destination: /tmp/sim2real\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("appspec.yml", appspec)
    put_resp = s3.put_object(Bucket=bucket, Key="revision.zip", Body=buf.getvalue())
    etag = put_resp["ETag"].strip('"')
    return {
        "revisionType": "S3",
        "s3Location": {"bucket": bucket, "key": "revision.zip", "bundleType": "zip", "eTag": etag},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
