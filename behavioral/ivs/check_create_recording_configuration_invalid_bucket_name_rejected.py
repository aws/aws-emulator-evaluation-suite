"""create-recording-configuration-invalid-bucket-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-recording-configuration-invalid-bucket-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRecordingConfiguration with an invalid bucket name (uppercase, underscore) fails ValidationException
    with the exact message and creates nothing, while an owned valid bucket succeeds."""
    ivs = ctx.client("ivs")
    s3 = ctx.client("s3")

    bad_bucket = "Invalid_Bucket_Name_" + ctx.unique_name("x").replace("-", "")
    error = _client_error(
        lambda: ivs.create_recording_configuration(
            name=ctx.unique_name("sim2real-ivs-badbucket-"),
            destinationConfiguration={"s3": {"bucketName": bad_bucket}},
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "CreateRecordingConfiguration.destinationConfiguration.s3.bucketName does not match "
        "the required pattern ^[a-z0-9-.]+$"
    ), f"unexpected validation message for an invalid bucket name: {error['Message']!r}"

    present = [
        c for c in _all_recording_configurations(ivs)
        if c.get("destinationConfiguration", {}).get("s3", {}).get("bucketName")
        == bad_bucket
    ]
    assert present == [], f"a config referencing the invalid bucket name exists: {present}"

    good_bucket = ctx.unique_name("sim2real-ivs-goodbucket-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region where S3's CreateBucket rejects an explicit
        # LocationConstraint; every other region requires one. Not a region pin —
        # this branches on the S3 API's own quirk, not on where the test runs.
        s3.create_bucket(Bucket=good_bucket)
    else:
        s3.create_bucket(
            Bucket=good_bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=good_bucket))

    cfg_arn = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-goodbucket-cfg-"),
        destinationConfiguration={"s3": {"bucketName": good_bucket}},
        tags={"sim2real-check": CHECK},
    )["recordingConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=cfg_arn))
    got = ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"]
    assert got["destinationConfiguration"]["s3"]["bucketName"] == good_bucket, (
        f"expected bucketName {good_bucket!r}, got "
        f"{got['destinationConfiguration']['s3'].get('bucketName')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _all_recording_configurations(ivs):
    out = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = ivs.list_recording_configurations(**kwargs)
        out.extend(resp["recordingConfigurations"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
