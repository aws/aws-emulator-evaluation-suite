"""s3unicode-copy-source-with-plus-and-percent-resolves-literally."""

from __future__ import annotations

import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-copy-source-with-plus-and-percent-resolves-literally"
GROUP = 'representation'
SERVICES = ['s3']

_NO_SUCH_KEY_MSG = 'The specified key does not exist.'


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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _list_keys(s3, bucket, prefix):
    """Every key under ``prefix``, across all pages."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject reads its copy-source key literally: '+', space, '%' and an emoji name the source.

    The copy is byte-identical with the same ETag; spelling '+' as a space is NoSuchKey and creates
    no destination object.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    emoji = "\U0001f600"
    src_prefix = "cpsrc/"
    dst_prefix = "cpdst/"
    src_key = f"{src_prefix}a+b c%20d-{emoji}.bin"
    dst_key = f"{dst_prefix}{emoji} plus+pct%25 café.bin"
    body = b"\x00\xff\xfe" + emoji.encode("utf-8") + b"copy-source-payload\r\n"

    s3.put_object(Bucket=bucket, Key=src_key, Body=body)
    src_etag = s3.head_object(Bucket=bucket, Key=src_key)["ETag"]
    assert src_etag.strip('"') == hashlib.md5(body).hexdigest(), (
        f"the source object's ETag is not the MD5 of the bytes we sent: {src_etag!r} vs "
        f"{hashlib.md5(body).hexdigest()!r}"
    )

    # --- The copy resolves the reserved-character source and lands byte-identical.
    copied = s3.copy_object(
        Bucket=bucket, Key=dst_key, CopySource={"Bucket": bucket, "Key": src_key}
    )
    assert copied["CopyObjectResult"]["ETag"] == src_etag, (
        f"the copy's ETag does not match the source's: {copied['CopyObjectResult']['ETag']!r} vs "
        f"{src_etag!r} -- the content changed while being copied"
    )
    got = s3.get_object(Bucket=bucket, Key=dst_key)["Body"].read()
    assert got == body, (
        f"the copied object's bytes differ from the source's: sent {body!r}, got {got!r}"
    )

    # --- The destination key -- itself full of reserved characters -- lists back byte-exactly.
    listed = _list_keys(s3, bucket, dst_prefix)
    assert listed == [dst_key], (
        f"ListObjectsV2 did not return exactly the copy destination: expected [{dst_key!r}], got "
        f"{listed!r}"
    )
    assert listed[0].encode("utf-8") == dst_key.encode("utf-8"), (
        f"the listed destination key's bytes differ from the requested key's: listed "
        f"{listed[0].encode('utf-8')!r}, requested {dst_key.encode('utf-8')!r}"
    )

    # --- Break exactly one thing: spell the source's '+' as a space.
    bad_source = src_key.replace("a+b", "a b")
    assert bad_source != src_key, "test setup error: the '+'-as-space source equals the real source"
    never_key = f"{dst_prefix}must-not-exist.bin"
    exc = _client_error(
        lambda: s3.copy_object(
            Bucket=bucket, Key=never_key, CopySource={"Bucket": bucket, "Key": bad_source}
        ),
        f"CopyObject accepted the source key {bad_source!r}, which no object has; the '+' in the "
        f"copy-source header is being form-decoded as a space",
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == "NoSuchKey", (
        f"expected NoSuchKey for a copy source that spells '+' as a space, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == _NO_SUCH_KEY_MSG, (
        f"expected message {_NO_SUCH_KEY_MSG!r}, got {message!r}"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for NoSuchKey, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Effect absent: the rejected copy created no destination object.
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=never_key),
                        f"the rejected copy created {never_key!r} anyway; the failure was not atomic")
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the object the rejected copy must not have created, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Positive control: the good copy is untouched by the rejection.
    assert _list_keys(s3, bucket, dst_prefix) == [dst_key], (
        f"the destination prefix changed after the rejected copy: "
        f"{_list_keys(s3, bucket, dst_prefix)!r}"
    )
    final = s3.get_object(Bucket=bucket, Key=dst_key)["Body"].read()
    assert final == body, (
        f"the good copy was altered by the rejected copy: expected {body!r}, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
