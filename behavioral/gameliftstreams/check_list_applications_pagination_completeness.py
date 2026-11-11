"""list-applications-pagination-completeness."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-applications-pagination-completeness"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging through ListApplications with a small MaxResults, following NextToken to
    completion, surfaces every application created in this test exactly once each."""
    s3 = ctx.client("s3")
    gls = ctx.client("gameliftstreams")
    created_ids: list[str] = []

    def _cleanup_all():
        for app_id in created_ids:
            _safe(lambda i=app_id: gls.delete_application(Identifier=i))

    ctx.on_cleanup(_cleanup_all)

    # Use a REAL (small) S3 object so CreateApplication's synchronous handling is exercised
    # the same way regardless of how deep its input validation goes -- this test cares about
    # ListApplications pagination, not application processing outcome.
    bucket = ctx.unique_name("sim2real-behav-gls-page-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content"
        )

    def _cleanup_bucket():
        try:
            s3.delete_object(Bucket=bucket, Key="app/run.sh")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_object(Bucket=bucket, Key="app/run.sh", Body=b"#!/bin/sh\nexit 0\n")

    source_uri = f"s3://{bucket}/app/"
    for i in range(3):
        resp = gls.create_application(
            Description=ctx.unique_name(f"sim2real-gls-app-{i}-"),
            RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
            ExecutablePath="run.sh",
            ApplicationSourceUri=source_uri,
        )
        created_ids.append(resp["Id"])

    seen: list[str] = []
    next_token = None
    while True:
        kwargs = {"MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = gls.list_applications(**kwargs)
        items = page["Items"]
        assert len(items) <= 1, f"MaxResults=1 but page returned {len(items)} items"
        seen.extend(item["Id"] for item in items)
        next_token = page.get("NextToken")
        if not next_token:
            break

    for app_id in created_ids:
        count = seen.count(app_id)
        assert count == 1, f"application {app_id} appeared {count} times across paginated listing (expected exactly once)"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
