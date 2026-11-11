"""list-objects-nosuchbucket."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-objects-nosuchbucket"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjects against a bucket that does not exist returns NoSuchBucket rather
    than an empty listing."""
    s3 = ctx.client("s3")

    # Positive control: ListObjects succeeds against a bucket that does exist, so the
    # negative below cannot pass merely because ListObjects is broken outright.
    bucket = _new_bucket(ctx, s3)
    resp = s3.list_objects(Bucket=bucket)
    assert resp.get("Contents", []) == [], f"expected empty listing, got {resp.get('Contents')}"

    # Break the one precondition: bucket existence.
    missing_bucket = ctx.unique_name("sim2real-nobucket-")
    err = _client_error(lambda: s3.list_objects(Bucket=missing_bucket))
    assert err.get("Code") == "NoSuchBucket", f"expected NoSuchBucket, got {err!r}"
    assert err.get("Message") == "The specified bucket does not exist", err

    # Independent read: the failed call did not create the bucket as a side effect.
    existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    assert missing_bucket not in existing, (
        f"{missing_bucket} unexpectedly exists after a failed ListObjects call"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-lsctrl-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
