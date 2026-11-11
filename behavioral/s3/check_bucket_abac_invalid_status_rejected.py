"""bucket-abac-invalid-status-rejected."""

from __future__ import annotations
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "bucket-abac-invalid-status-rejected"
GROUP = 'acls_policies'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE GUARD: PutBucketAbac with a Status value outside the Enabled/Disabled
    enum MUST be rejected, not silently accepted/coerced, and the bucket's ABAC status must
    remain unchanged by the rejected call."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    try:
        before = s3.get_bucket_abac(Bucket=bucket)["AbacStatus"]["Status"]

        code, message = _client_error(
            lambda: s3.put_bucket_abac(Bucket=bucket, AbacStatus={"Status": "NotARealValue"})
        )
        assert code == "MalformedXML", f"expected MalformedXML for an invalid ABAC Status, got {code!r}"
        expected = (
            "The XML you provided was not well-formed or did not validate against our published schema"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"

        # effect absent: the rejected call must not have changed the bucket's ABAC status
        after = s3.get_bucket_abac(Bucket=bucket)["AbacStatus"]["Status"]
        assert after == before, f"ABAC status changed from {before!r} to {after!r} despite rejection"

        # positive control: a valid Status value on the same bucket is accepted and takes effect,
        # so the rejection above is specific to the bad value, not a blanket denial
        other = "Disabled" if before == "Enabled" else "Enabled"
        s3.put_bucket_abac(Bucket=bucket, AbacStatus={"Status": other})
        got = s3.get_bucket_abac(Bucket=bucket)["AbacStatus"]["Status"]
        assert got == other, f"expected valid Status {other!r} to take effect, got {got!r}"
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks PutBucketAbac support: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
