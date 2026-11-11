"""create-storage-location-idempotent."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "create-storage-location-idempotent"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStorageLocation is idempotent and returns a real, existing account-level EB bucket."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    first = eb.create_storage_location()["S3Bucket"]
    second = eb.create_storage_location()["S3Bucket"]

    expected = f"elasticbeanstalk-{ctx.region}-{account}"
    assert first == expected, (
        f"the EB storage bucket must be named elasticbeanstalk-<region>-<account>, "
        f"expected {expected!r}, got {first!r}"
    )
    assert first == second, "repeated CreateStorageLocation must return the same bucket"

    # Independent read at the destination (S3, not EB): proves the name is a real bucket
    # that exists, not just a string echoed back by CreateStorageLocation's own response.
    try:
        s3.head_bucket(Bucket=first)
    except s3.exceptions.ClientError as exc:
        raise AssertionError(
            f"the EB storage bucket {first!r} must exist in S3, HeadBucket raised {exc!r}"
        ) from exc

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
