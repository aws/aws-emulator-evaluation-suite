"""list-objects-v1-basic-listing."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-objects-v1-basic-listing"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ListObjects enumerates keys in a real bucket, NoSuchBucket for a missing one."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    keys = ["alpha.txt", "beta.txt", "gamma/nested.txt"]
    for k in keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"payload")

    listed = s3.list_objects(Bucket=bucket)
    names = sorted(o["Key"] for o in listed.get("Contents", []))
    assert names == sorted(keys), f"expected {sorted(keys)}, got {names}"
    assert listed["Name"] == bucket, f"expected Name={bucket!r}, got {listed['Name']!r}"
    assert listed["IsTruncated"] is False, f"expected IsTruncated=False, got {listed['IsTruncated']!r}"
    assert listed["MaxKeys"] == 1000, f"expected the documented default MaxKeys=1000, got {listed['MaxKeys']!r}"

    # Positive control established above; now break the one precondition: bucket existence.
    missing_bucket = ctx.unique_name("sim2real-s3-missing-").lower()
    err = _client_error(lambda: s3.list_objects(Bucket=missing_bucket))
    assert err.get("Code") == "NoSuchBucket", f"expected NoSuchBucket, got {err!r}"
    assert err.get("Message") == "The specified bucket does not exist", err

    # The forbidden call did not create a bucket as a side effect.
    existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    assert missing_bucket not in existing, f"{missing_bucket} unexpectedly exists after a failed ListObjects call"

    # Restore: the missing precondition is bucket existence, and unlike a malformed input it can
    # be fixed within the check — creating the bucket must make the identical call succeed.
    _new_bucket(ctx, s3, name=missing_bucket)
    restored = s3.list_objects(Bucket=missing_bucket)
    assert restored.get("Contents", []) == [], (
        f"expected an empty listing for the newly-created {missing_bucket}, "
        f"got {restored.get('Contents')!r}"
    )


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _new_bucket(ctx, s3, name=None):
    name = (name or ctx.unique_name("sim2real-s3-behav-")).lower()
    kwargs = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; every other
    # region requires one naming itself, so this is a region-pin workaround, not a literal.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=name)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
