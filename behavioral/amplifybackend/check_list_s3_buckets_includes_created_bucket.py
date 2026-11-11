"""list-s3-buckets-includes-created-bucket."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-s3-buckets-includes-created-bucket"
GROUP = "cross-service"
SERVICES = ["amplifybackend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListS3Buckets reflects an S3 bucket that actually exists in the caller's account."""
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-ab-bucket-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )

    ab = ctx.client("amplifybackend")
    names = set()
    next_token = None
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        page = ab.list_s3_buckets(**kwargs)
        names.update(b["Name"] for b in page.get("Buckets", []))
        next_token = page.get("NextToken")
        if bucket_name in names or not next_token:
            break

    assert bucket_name in names, f"{bucket_name} not found in ListS3Buckets output"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
