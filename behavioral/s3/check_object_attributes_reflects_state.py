"""object-attributes-reflects-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-attributes-reflects-state"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectAttributes tracks ETag/size/class through create, delete-then-unusable, and recreate."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-attrs-")
    _create_bucket(s3, ctx, bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "attributes-object.bin"
    body = b"attribute-tracking-payload" * 10
    put = s3.put_object(Bucket=bucket, Key=key, Body=body)
    put_etag = put["ETag"].strip('"')

    attrs = s3.get_object_attributes(
        Bucket=bucket, Key=key, ObjectAttributes=["ETag", "ObjectSize", "StorageClass"]
    )
    assert attrs["ETag"].strip('"') == put_etag, f"ETag mismatch: {attrs['ETag']} vs {put_etag}"
    assert attrs["ObjectSize"] == len(body), f"ObjectSize mismatch: {attrs['ObjectSize']} vs {len(body)}"
    # STANDARD is the default storage class and is often omitted rather than echoed back.
    assert attrs.get("StorageClass") in (None, "STANDARD"), f"unexpected StorageClass: {attrs.get('StorageClass')}"

    s3.delete_object(Bucket=bucket, Key=key)

    code, message = _error(
        lambda: s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ETag", "ObjectSize"])
    )
    assert code == "NoSuchKey", f"expected NoSuchKey after delete, got {code}"
    assert message == "The specified key does not exist.", f"unexpected NoSuchKey message: {message!r}"

    # The deleted id isn't just unread — it's unusable: a mutation against it fails the same way.
    tag_code, tag_message = _error(
        lambda: s3.put_object_tagging(
            Bucket=bucket, Key=key, Tagging={"TagSet": [{"Key": "k", "Value": "v"}]}
        )
    )
    assert tag_code == "NoSuchKey", f"expected a mutation on the deleted key to fail too, got {tag_code}"
    assert tag_message == "The specified key does not exist.", f"unexpected NoSuchKey message: {tag_message!r}"

    # The identifier is reusable, and attributes reflect the NEW state, not the deleted one.
    new_body = b"post-delete-replacement-payload" * 5
    put2 = s3.put_object(Bucket=bucket, Key=key, Body=new_body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    put2_etag = put2["ETag"].strip('"')

    attrs2 = s3.get_object_attributes(Bucket=bucket, Key=key, ObjectAttributes=["ETag", "ObjectSize"])
    assert attrs2["ETag"].strip('"') == put2_etag, f"ETag mismatch after recreate: {attrs2['ETag']} vs {put2_etag}"
    assert attrs2["ObjectSize"] == len(new_body), (
        f"ObjectSize mismatch after recreate: {attrs2['ObjectSize']} vs {len(new_body)}"
    )
    assert attrs2["ETag"].strip('"') != put_etag, "recreated object still reports the deleted object's ETag"


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
