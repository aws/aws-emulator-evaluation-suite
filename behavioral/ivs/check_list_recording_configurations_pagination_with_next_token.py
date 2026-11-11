"""list-recording-configurations-pagination-with-next-token."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-recording-configurations-pagination-with-next-token"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRecordingConfigurations with maxResults=1 pages through results via nextToken,
    returning every created configuration exactly once."""
    ivs = ctx.client("ivs")
    created_arns = set()
    for _ in range(3):
        bucket = _create_bucket(ctx)
        rc = ivs.create_recording_configuration(
            name=ctx.unique_name("sim2real-ivs-page-"),
            destinationConfiguration={"s3": {"bucketName": bucket}},
            tags={"sim2real": CHECK},
        )["recordingConfiguration"]
        ctx.on_cleanup(lambda arn=rc["arn"]: ivs.delete_recording_configuration(arn=arn))
        created_arns.add(rc["arn"])

    seen_arns: list[str] = []
    next_token = None
    pages = 0
    for _ in range(200):  # hard cap so a broken emulator can't loop forever
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = ivs.list_recording_configurations(**kwargs)
        got = len(page["recordingConfigurations"])
        assert got <= 1, f"maxResults=1 but ListRecordingConfigurations returned {got} items"
        pages += 1
        for rc in page["recordingConfigurations"]:
            seen_arns.append(rc["arn"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert pages >= 3, f"expected >=3 pages for 3 configs at maxResults=1, got {pages}"
    # Every one of our created configs must show up, and none of our own arns duplicated.
    our_seen = [arn for arn in seen_arns if arn in created_arns]
    missing = created_arns - set(our_seen)
    assert set(our_seen) == created_arns, f"paginated results never surfaced: {missing}"
    dupes = [arn for arn in set(our_seen) if our_seen.count(arn) > 1]
    assert len(our_seen) == len(set(our_seen)), f"arn(s) seen on more than one page: {dupes}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ivs-pg-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
