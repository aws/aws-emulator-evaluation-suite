"""s3unicode-object-tag-value-with-an-astral-emoji-rejected."""

from __future__ import annotations

import unicodedata

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-object-tag-value-with-an-astral-emoji-rejected"
GROUP = 'errors'
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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Object tag values accept NFC accented letters and CJK byte-exactly, but an astral-plane
    character and an NFD combining mark are each refused with InvalidTag, leaving the tag set as is.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    emoji = "\U0001f600"
    key = "tag/obj.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"tagged")

    # Built from codepoints so no editor or formatter can silently normalise the NFD form to NFC.
    nfc = "caf" + chr(0x00E9)                  # LATIN SMALL LETTER E WITH ACUTE
    nfd = "caf" + chr(0x0065) + chr(0x0301)    # LATIN SMALL LETTER E + COMBINING ACUTE ACCENT
    cjk = chr(0x65E5) + chr(0x672C) + chr(0x8A9E)  # CJK, three UTF-8 bytes each
    assert unicodedata.normalize("NFC", nfd) == nfc and nfd != nfc, (
        f"test setup error: {nfd!r} is not the NFD form of {nfc!r}"
    )

    # --- Accepted side: three non-ASCII values that S3 does allow, stored byte-exactly.
    accepted = [
        {"Key": "sim2real-plain", "Value": "PLAIN-ASCII"},
        {"Key": "sim2real-nfc", "Value": nfc},
        {"Key": "sim2real-cjk", "Value": cjk},
    ]
    s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={"TagSet": accepted})
    stored = s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    as_map = {t["Key"]: t["Value"] for t in stored}
    assert as_map == {t["Key"]: t["Value"] for t in accepted}, (
        f"the accepted tag set did not round-trip: wrote "
        f"{ {t['Key']: t['Value'] for t in accepted}!r }, read {as_map!r}"
    )
    assert as_map["sim2real-nfc"].encode("utf-8") == nfc.encode("utf-8"), (
        f"the precomposed tag value was re-encoded: wrote {nfc.encode('utf-8')!r}, read "
        f"{as_map['sim2real-nfc'].encode('utf-8')!r}"
    )
    assert as_map["sim2real-cjk"].encode("utf-8") == cjk.encode("utf-8"), (
        f"the CJK tag value was re-encoded: wrote {cjk.encode('utf-8')!r}, read "
        f"{as_map['sim2real-cjk'].encode('utf-8')!r}"
    )

    # --- Break exactly one thing: one tag value becomes an astral-plane character.
    exc = _client_error(
        lambda: s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={"TagSet": [{"Key": "sim2real-astral", "Value": emoji}]},
        )
    )
    assert exc is not None, (
        f"PutObjectTagging accepted the astral-plane tag value {emoji!r}; real S3 refuses it, so "
        f"the tag-value character class is not being enforced"
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == "InvalidTag", (
        f"expected InvalidTag for an astral-plane tag value, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The TagValue you have provided is invalid", f"unexpected message {message!r}"
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400 for InvalidTag, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Effect absent: the refused call replaced nothing. PutObjectTagging is a whole-set
    #     replacement, so a partially applied refusal would be visible as a lost tag set.
    after_astral = {
        t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    }
    assert after_astral == as_map, (
        f"the refused astral tag value changed the stored tag set: was {as_map!r}, now "
        f"{after_astral!r}"
    )

    # --- The same boundary, from the other side of Unicode equivalence: the NFD spelling of an
    #     ACCEPTED value is refused with the same code.
    exc = _client_error(
        lambda: s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={"TagSet": [{"Key": "sim2real-nfd", "Value": nfd}]},
        )
    )
    assert exc is not None, (
        f"PutObjectTagging accepted the decomposed tag value {nfd!r} while real S3 refuses it, even "
        f"though it accepts the canonically equivalent {nfc!r}; the validator is normalising before "
        f"it checks"
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == "InvalidTag", (
        f"expected InvalidTag for a tag value containing a combining mark, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The TagValue you have provided is invalid", f"unexpected message {message!r}"

    # --- Effect absent again, and positive control: the accepted set is still exactly what it was.
    final = {
        t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    }
    assert final == as_map, (
        f"the refused decomposed tag value changed the stored tag set: was {as_map!r}, now "
        f"{final!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == b"tagged", (
        "the object's content was disturbed by the refused tagging calls"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
