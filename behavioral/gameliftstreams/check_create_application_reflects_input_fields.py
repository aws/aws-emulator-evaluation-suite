"""create-application-reflects-input-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-reflects-input-fields"
GROUP = "control-plane"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApplication echoes the submitted fields and GetApplication returns the same values."""
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")
    desc = ctx.unique_name("sim2real-behav-gls-app-")
    exec_path = "start.sh"
    runtime = {"Type": "UBUNTU", "Version": "22_04_LTS"}

    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        # us-east-1 is the S3 default region: CreateBucket rejects an explicit
        # LocationConstraint for it and requires the constraint everywhere else.
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key="build/start.sh", Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="build/start.sh"))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content for CreateApplication to succeed on"
        )
    # Submitted without a trailing slash; GameLiftStreams treats the URI as a prefix and
    # normalizes it to one on echo (confirmed against real AWS, not assumed).
    submitted_source_uri = f"s3://{bucket}/build"
    source_uri = submitted_source_uri + "/"

    created = gl.create_application(
        Description=desc,
        RuntimeEnvironment=runtime,
        ExecutablePath=exec_path,
        ApplicationSourceUri=submitted_source_uri,
        Tags={"sim2real-check": CHECK},
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: gl.delete_application(Identifier=arn))

    assert created["Description"] == desc, f"expected Description {desc!r}, got {created['Description']!r}"
    assert created["ExecutablePath"] == exec_path, (
        f"expected ExecutablePath {exec_path!r}, got {created['ExecutablePath']!r}"
    )
    assert created["ApplicationSourceUri"] == source_uri, (
        f"expected ApplicationSourceUri {source_uri!r}, got {created['ApplicationSourceUri']!r}"
    )
    assert created["RuntimeEnvironment"]["Type"] == "UBUNTU", (
        f"expected RuntimeEnvironment.Type UBUNTU, got {created['RuntimeEnvironment']['Type']!r}"
    )
    assert created["RuntimeEnvironment"]["Version"] == "22_04_LTS", (
        f"expected RuntimeEnvironment.Version 22_04_LTS, got {created['RuntimeEnvironment']['Version']!r}"
    )
    assert created["Status"] in ("INITIALIZED", "PROCESSING"), (
        f"expected Status in (INITIALIZED, PROCESSING), got {created['Status']!r}"
    )

    fetched = gl.get_application(Identifier=arn)
    assert fetched["Arn"] == arn, f"expected Arn {arn!r}, got {fetched['Arn']!r}"
    assert fetched["Id"] == created["Id"], f"expected Id {created['Id']!r}, got {fetched['Id']!r}"
    assert fetched["Description"] == desc, f"expected Description {desc!r}, got {fetched['Description']!r}"
    assert fetched["ExecutablePath"] == exec_path, (
        f"expected ExecutablePath {exec_path!r}, got {fetched['ExecutablePath']!r}"
    )
    assert fetched["ApplicationSourceUri"] == source_uri, (
        f"expected ApplicationSourceUri {source_uri!r}, got {fetched['ApplicationSourceUri']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
