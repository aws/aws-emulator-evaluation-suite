"""s3unicode-combining-marks-in-a-key-are-not-normalised."""

from __future__ import annotations

import unicodedata

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-combining-marks-in-a-key-are-not-normalised"
GROUP = 'representation'
SERVICES = ['s3']


# ===== helpers (self-contained) =====
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


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None
# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """NFC and NFD spellings of the same key are two DIFFERENT objects: S3 does not normalise keys.

    Both bodies read back, the mark-stripped ASCII spelling is a 404, and deleting one form leaves
    the other intact, which a normalising store cannot do.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    prefix = "norm/"
    # Built from codepoints, not written as literal characters: a literal decomposed sequence
    # in a source file is exactly the thing an editor, a formatter or a copy-paste silently
    # normalises away, and a check whose NFD key has quietly become NFC asserts nothing about
    # normalisation. This spelling cannot be folded by anything that touches the file.
    nfc = "caf" + chr(0x00E9)                  # LATIN SMALL LETTER E WITH ACUTE
    nfd = "caf" + chr(0x0065) + chr(0x0301)    # LATIN SMALL LETTER E + COMBINING ACUTE ACCENT
    key_nfc = f"{prefix}{nfc}.txt"
    key_nfd = f"{prefix}{nfd}.txt"
    body_nfc = b"body-stored-under-the-PRECOMPOSED-key"
    body_nfd = b"body-stored-under-the-DECOMPOSED-key"

    # --- Setup assertions: the two keys are canonical equivalents that differ in bytes.
    assert nfc != nfd, "test setup error: the two spellings are identical strings"
    assert unicodedata.normalize("NFC", nfd) == nfc, (
        f"test setup error: NFC({nfd!r}) is {unicodedata.normalize('NFC', nfd)!r}, not {nfc!r}"
    )
    assert unicodedata.normalize("NFD", nfc) == nfd, (
        f"test setup error: NFD({nfc!r}) is {unicodedata.normalize('NFD', nfc)!r}, not {nfd!r}"
    )
    assert len(nfc.encode("utf-8")) == 5 and len(nfd.encode("utf-8")) == 6, (
        f"test setup error: expected 5 and 6 UTF-8 bytes, got "
        f"{len(nfc.encode('utf-8'))} and {len(nfd.encode('utf-8'))}"
    )

    # --- Write both. Distinct bodies, so a collapse is visible as a lost body and not just a
    #     lost key.
    s3.put_object(Bucket=bucket, Key=key_nfc, Body=body_nfc)
    s3.put_object(Bucket=bucket, Key=key_nfd, Body=body_nfd)

    # --- Both identities exist, and the listing reports each spelling byte-exactly.
    listed = sorted(_list_keys(s3, bucket, prefix))
    assert listed == sorted([key_nfc, key_nfd]), (
        f"the NFC and NFD keys are not two distinct objects in ListObjectsV2: expected "
        f"{sorted([key_nfc, key_nfd])!r}, got {listed!r} -- a listing of length 1 means the keys "
        f"were normalised and one object was overwritten"
    )
    assert sorted(k.encode("utf-8") for k in listed) == sorted(
        [key_nfc.encode("utf-8"), key_nfd.encode("utf-8")]
    ), (
        f"the listed keys' UTF-8 bytes differ from the written keys': listed "
        f"{[k.encode('utf-8') for k in listed]!r}"
    )

    # --- Each key returns ITS OWN body. Aliasing would cross the two.
    got_nfc = s3.get_object(Bucket=bucket, Key=key_nfc)["Body"].read()
    assert got_nfc == body_nfc, (
        f"the precomposed key returned the wrong body: expected {body_nfc!r}, got {got_nfc!r}"
    )
    got_nfd = s3.get_object(Bucket=bucket, Key=key_nfd)["Body"].read()
    assert got_nfd == body_nfd, (
        f"the decomposed key returned the wrong body: expected {body_nfd!r}, got {got_nfd!r}"
    )

    # --- Effect absent: the mark-stripped ASCII spelling is not an alias for either object.
    key_stripped = f"{prefix}cafe.txt"
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_stripped))
    assert exc is not None, (
        f"the accent-stripped key {key_stripped!r} resolves to an object; combining marks are being "
        f"discarded from keys"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the accent-stripped key, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Transition: deleting one normalisation form leaves the other whole.
    s3.delete_object(Bucket=bucket, Key=key_nfd)
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_nfd))
    assert exc is not None, f"the decomposed key {key_nfd!r} survived its own delete"
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the deleted decomposed key, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    survivor = s3.get_object(Bucket=bucket, Key=key_nfc)["Body"].read()
    assert survivor == body_nfc, (
        f"deleting the decomposed key damaged the precomposed one: expected {body_nfc!r}, got "
        f"{survivor!r}"
    )
    assert _list_keys(s3, bucket, prefix) == [key_nfc], (
        f"after deleting only the decomposed key the listing should hold exactly {key_nfc!r}, got "
        f"{_list_keys(s3, bucket, prefix)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
