"""last-modified-whole-second-precision-agrees-and-advances."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "last-modified-whole-second-precision-agrees-and-advances"
GROUP = "representation"
SERVICES = ["s3"]

_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
_KEY = "ts.txt"

#: Bound on the server-clock barrier. LastModified has one-second resolution, so two writes inside
#: one server-second tie; the barrier waits for the S3 server's own clock to pass a given second.
_CLOCK_DEADLINE_S = 30.0


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only not-found is tolerated."""
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


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _server_now(s3, bucket: str):
    """The S3 server's own clock, read off a HeadBucket response's Date header (second resolution)."""
    hdrs = s3.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"]
    return parsedate_to_datetime(hdrs["date"])


def _after_second(s3, bucket: str, stamp) -> None:
    """Block until the SERVER clock is strictly past `stamp`'s second — a bounded poll, not a sleep."""
    deadline = time.monotonic() + _CLOCK_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        last = _server_now(s3, bucket)
        if last.replace(microsecond=0) > stamp.replace(microsecond=0):
            return
        time.sleep(0.25)
    raise AssertionError(
        f"the server clock never passed {stamp.isoformat()} within {_CLOCK_DEADLINE_S}s; last Date "
        f"header read {last!r}"
    )


def _list_objects_v2_xml_last_modified(s3, bucket: str, key: str) -> str:
    """The raw XML <LastModified> text for `key`, captured from the response before it is parsed."""
    captured: dict = {}

    def _capture(response_dict=None, **_kw):
        captured["body"] = response_dict["body"]

    s3.meta.events.register("before-parse.s3.ListObjectsV2", _capture)
    try:
        s3.list_objects_v2(Bucket=bucket)
    finally:
        s3.meta.events.unregister("before-parse.s3.ListObjectsV2", _capture)

    root = ET.fromstring(captured["body"])
    for contents in root.findall(f"{_NS}Contents"):
        if contents.findtext(f"{_NS}Key") == key:
            text = contents.findtext(f"{_NS}LastModified")
            assert text, f"ListObjectsV2 XML has no LastModified for key {key!r}"
            return text
    raise AssertionError(f"key {key!r} is not present in the ListObjectsV2 XML")


def _parse_xml_timestamp(text: str) -> datetime:
    """Parse an S3 XML LastModified value (an ISO-8601, 'Z'-suffixed timestamp) into a UTC datetime."""
    assert text.endswith("Z"), f"XML LastModified {text!r} is not UTC ('Z')-suffixed"
    return datetime.fromisoformat(text[:-1]).replace(tzinfo=timezone.utc)


def _read_last_modified(s3, bucket: str, key: str):
    """(raw XML text, XML LastModified, GetObjectAttributes LastModified, HeadObject LastModified)."""
    xml_text = _list_objects_v2_xml_last_modified(s3, bucket, key)
    xml_lm = _parse_xml_timestamp(xml_text)
    attrs_lm = s3.get_object_attributes(
        Bucket=bucket, Key=key, ObjectAttributes=["ETag"]
    )["LastModified"]
    head_lm = s3.head_object(Bucket=bucket, Key=key)["LastModified"]
    return xml_text, xml_lm, attrs_lm, head_lm


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectsV2's XML, GetObjectAttributes and HeadObject report an object's LastModified at
    whole-second precision and agree to the second; a later PutObject strictly advances all three.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    s3.put_object(Bucket=bucket, Key=_KEY, Body=b"first")
    xml_text1, xml_lm1, attrs_lm1, head_lm1 = _read_last_modified(s3, bucket, _KEY)

    assert xml_text1.endswith(".000Z"), (
        f"ListObjectsV2 XML LastModified {xml_text1!r} does not end in '.000Z'"
    )
    assert attrs_lm1.microsecond == 0, (
        f"GetObjectAttributes LastModified {attrs_lm1.isoformat()!r} carries a sub-second component"
    )
    assert head_lm1.microsecond == 0, (
        f"HeadObject Last-Modified {head_lm1.isoformat()!r} carries a sub-second component"
    )
    assert xml_lm1 == attrs_lm1 == head_lm1, (
        f"the three reads disagree to the second: list={xml_lm1.isoformat()!r} "
        f"attrs={attrs_lm1.isoformat()!r} head={head_lm1.isoformat()!r}"
    )

    _after_second(s3, bucket, head_lm1)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=b"second")
    xml_text2, xml_lm2, attrs_lm2, head_lm2 = _read_last_modified(s3, bucket, _KEY)

    assert xml_text2.endswith(".000Z"), (
        f"ListObjectsV2 XML LastModified {xml_text2!r} does not end in '.000Z'"
    )
    assert attrs_lm2.microsecond == 0, (
        f"GetObjectAttributes LastModified {attrs_lm2.isoformat()!r} carries a sub-second component"
    )
    assert head_lm2.microsecond == 0, (
        f"HeadObject Last-Modified {head_lm2.isoformat()!r} carries a sub-second component"
    )
    assert xml_lm2 == attrs_lm2 == head_lm2, (
        f"the three reads disagree to the second after the second write: list={xml_lm2.isoformat()!r} "
        f"attrs={attrs_lm2.isoformat()!r} head={head_lm2.isoformat()!r}"
    )

    assert xml_lm2 > xml_lm1, (
        f"ListObjectsV2 LastModified did not advance: {xml_lm1.isoformat()!r} -> {xml_lm2.isoformat()!r}"
    )
    assert attrs_lm2 > attrs_lm1, (
        f"GetObjectAttributes LastModified did not advance: "
        f"{attrs_lm1.isoformat()!r} -> {attrs_lm2.isoformat()!r}"
    )
    assert head_lm2 > head_lm1, (
        f"HeadObject Last-Modified did not advance: {head_lm1.isoformat()!r} -> {head_lm2.isoformat()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
