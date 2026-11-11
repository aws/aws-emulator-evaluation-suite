"""create-recording-configuration-invalid-bucket-create-failed."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-recording-configuration-invalid-bucket-create-failed"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRecordingConfiguration on a well-formed but non-existent bucket fails ValidationException with the
    exact message and creates nothing, while an owned bucket is accepted."""
    ivs = ctx.client("ivs")
    bogus_bucket = ctx.unique_name("sim2real-ivs-missing-bucket-").lower()
    bad_name = ctx.unique_name("sim2real-ivs-rec-")

    before = {r["arn"] for r in _all_recording_configurations(ivs)}
    error = _client_error(
        lambda: ivs.create_recording_configuration(
            name=bad_name, destinationConfiguration={"s3": {"bucketName": bogus_bucket}}
        )
    )
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == (
        "Request member: recordingConfiguration.destinationConfiguration.s3 failed to satisfy "
        "the constraints: recordingConfiguration.destinationConfiguration.s3 is invalid"
    ), f"unexpected validation message for a nonexistent bucket: {error['Message']!r}"

    after = {r["arn"] for r in _all_recording_configurations(ivs)}
    assert after == before, (
        f"a recording configuration was created against a nonexistent bucket: {after - before}"
    )

    # Positive control: the identical shape of call against a real, owned bucket succeeds.
    good_bucket = ctx.unique_name("sim2real-ivs-goodbucket-").lower()
    s3 = ctx.client("s3")
    # us-east-1 literal: S3's CreateBucket rejects an explicit LocationConstraint for its own
    # default region, so the branch is on S3's API quirk, not a pin of this check's own region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=good_bucket)
    else:
        s3.create_bucket(
            Bucket=good_bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=good_bucket))

    good_name = ctx.unique_name("sim2real-ivs-rec-")
    cfg = ivs.create_recording_configuration(
        name=good_name, destinationConfiguration={"s3": {"bucketName": good_bucket}}
    )["recordingConfiguration"]
    ctx.on_cleanup(lambda: ivs.delete_recording_configuration(arn=cfg["arn"]))

    got = ivs.get_recording_configuration(arn=cfg["arn"])["recordingConfiguration"]
    got_bucket = got["destinationConfiguration"]["s3"]["bucketName"]
    assert got_bucket == good_bucket, f"expected bucketName {good_bucket!r}, got {got_bucket!r}"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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

