"""s3-delete-object-tagging-clears-only-the-addressed-version-tag-set."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-delete-object-tagging-clears-only-the-addressed-version-tag-set"
GROUP = 'tagging'
SERVICES = ['s3']

_BODY_V1 = b"first-generation-payload-that-a-tag-delete-must-not-touch" * 4
_BODY_V2 = b"second-generation-payload-that-a-tag-delete-must-not-touch" * 4
_BODY_V3 = b"third-generation-payload-destined-to-be-permanently-deleted" * 4


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
    # us-east-1 is the one region whose CreateBucket rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn, what):
    """Call fn() and return the ClientError it raised; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected {what} to be refused with a ClientError, but it succeeded")


def _all_versions(s3, bucket):
    """Fully paginated (Versions, DeleteMarkers) for a bucket."""
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjectTagging clears only the addressed version's tag set; the object is unchanged.

    A pinned or unversioned (current-version) delete leaves sibling versions' tags intact, and a
    delete aimed at a permanently deleted version is refused 404 NoSuchVersion.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert status == "Enabled", f"versioning did not take effect: Status is {status!r}"

    key = "per-version-tag-set.bin"

    # --- Three generations of one key, each carrying its own one-tag tag set. Setup deliberately
    # uses only the UNVERSIONED PutObjectTagging, which lands on whichever version is current at
    # that moment — i.e. the one just written. Every version-scoping claim this check makes is
    # therefore carried by a graded assertion below rather than smuggled into the setup.
    puts = []
    for body, value in ((_BODY_V1, "first"), (_BODY_V2, "second"), (_BODY_V3, "third")):
        puts.append(s3.put_object(Bucket=bucket, Key=key, Body=body))
        s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={"TagSet": [{"Key": "generation", "Value": value}]},
        )
    put1, put2, put3 = puts
    v1, v2, v3 = put1["VersionId"], put2["VersionId"], put3["VersionId"]
    assert len({v1, v2, v3}) == 3, (
        f"three PUTs into a versioned bucket must mint three distinct version ids, got "
        f"{[v1, v2, v3]!r}"
    )
    for label, vid in (("v1", v1), ("v2", v2), ("v3", v3)):
        assert vid and vid != "null", (
            f"{label} came back with VersionId {vid!r}; a PUT into a versioned bucket must mint "
            "a real version id"
        )
    etag1, etag2 = put1["ETag"], put2["ETag"]

    # --- Baseline: each version answers with its own tag set, and the unversioned read resolves
    # to the newest version. If this disagrees the rest of the check is meaningless.
    for vid, value in ((v1, "first"), (v2, "second"), (v3, "third")):
        got = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=vid)
        assert got["TagSet"] == [{"Key": "generation", "Value": value}], (
            f"baseline tag set for version {vid!r} is {got['TagSet']!r}, want the single tag "
            f"generation={value!r} — the three versions' tag sets are not independent"
        )
        assert got.get("VersionId") == vid, (
            f"GetObjectTagging pinned to {vid!r} echoed VersionId {got.get('VersionId')!r}"
        )
    latest_tags = s3.get_object_tagging(Bucket=bucket, Key=key)
    assert latest_tags.get("VersionId") == v3, (
        f"the unversioned GetObjectTagging resolved to {latest_tags.get('VersionId')!r}, want the "
        f"current version {v3!r}"
    )
    assert latest_tags["TagSet"] == [{"Key": "generation", "Value": "third"}], (
        f"the unversioned read returned {latest_tags['TagSet']!r}, want the current version's tag "
        "generation='third'"
    )

    # --- Negative leg: permanently remove v3, then aim a tag delete at its now-dead version id.
    # A VersionId is an address, not a hint, so S3 refuses this rather than resolving it to the
    # current version (which would clear v2's tags).
    s3.delete_object(Bucket=bucket, Key=key, VersionId=v3)
    refused = _client_error(
        lambda: s3.delete_object_tagging(Bucket=bucket, Key=key, VersionId=v3),
        f"DeleteObjectTagging aimed at the permanently-deleted version {v3!r}",
    )
    # The S3 Smithy model declares no `errors` array for DeleteObjectTagging; the code, message and
    # status below are the ones real AWS was observed to return for this exact request.
    refused_code = refused.response["Error"]["Code"]
    refused_message = refused.response["Error"]["Message"]
    refused_status = refused.response["ResponseMetadata"]["HTTPStatusCode"]
    assert refused_code == "NoSuchVersion", (
        f"expected error code 'NoSuchVersion' for a tag delete on the permanently-deleted "
        f"version {v3!r}, got {refused_code!r}"
    )
    assert refused_message == "The specified version does not exist.", (
        f"expected error message 'The specified version does not exist.' for a tag delete on the "
        f"permanently-deleted version {v3!r}, got {refused_message!r}"
    )
    assert refused_status == 404, (
        f"expected HTTP 404 for NoSuchVersion on the permanently-deleted version {v3!r}, got "
        f"{refused_status!r}"
    )
    for vid, value in ((v1, "first"), (v2, "second")):
        survived = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=vid)
        assert survived["TagSet"] == [{"Key": "generation", "Value": value}], (
            f"the refused tag delete disturbed version {vid!r}: its tag set is now "
            f"{survived['TagSet']!r}, want generation={value!r}"
        )

    # --- Positive leg A: clear the tag set of the NON-current version. The transition is v1's
    # tag set emptying; the invariant is v2's tag set NOT emptying.
    cleared_v1 = s3.delete_object_tagging(Bucket=bucket, Key=key, VersionId=v1)
    assert cleared_v1.get("VersionId") == v1, (
        f"the tag delete pinned to {v1!r} echoed VersionId {cleared_v1.get('VersionId')!r}; the "
        "response must name the version it actually operated on"
    )
    after_v1 = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=v1)
    assert after_v1["TagSet"] == [], (
        f"version {v1!r} still reports tags after its tag set was deleted: {after_v1['TagSet']!r}"
    )
    sibling = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=v2)
    assert sibling["TagSet"] == [{"Key": "generation", "Value": "second"}], (
        f"deleting version {v1!r}'s tag set also cleared sibling version {v2!r}, whose tag set is "
        f"now {sibling['TagSet']!r} instead of generation='second' — tag sets are being stored "
        "per key rather than per version"
    )
    unversioned_after_v1 = s3.get_object_tagging(Bucket=bucket, Key=key)
    assert unversioned_after_v1.get("VersionId") == v2, (
        f"the unversioned read now resolves to {unversioned_after_v1.get('VersionId')!r}, want "
        f"the current version {v2!r}"
    )
    assert unversioned_after_v1["TagSet"] == [{"Key": "generation", "Value": "second"}], (
        f"the unversioned read returned {unversioned_after_v1['TagSet']!r}; deleting an older "
        "version's tag set must not change what the current version reports"
    )

    # --- Re-tag the already-cleared non-current version. Without this the unversioned leg below
    # would run with every surviving sibling already empty, and a key-wide tag delete would
    # satisfy it by accident. A distinct value also proves a version whose tag set was deleted
    # can be re-tagged, version-scoped.
    s3.put_object_tagging(
        Bucket=bucket,
        Key=key,
        VersionId=v1,
        Tagging={"TagSet": [{"Key": "generation", "Value": "requeued"}]},
    )
    requeued = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=v1)
    assert requeued["TagSet"] == [{"Key": "generation", "Value": "requeued"}], (
        f"version {v1!r} did not take a fresh tag set after its tags were deleted: "
        f"{requeued['TagSet']!r}"
    )
    still_second = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=v2)
    assert still_second["TagSet"] == [{"Key": "generation", "Value": "second"}], (
        f"re-tagging version {v1!r} changed sibling version {v2!r}, whose tag set is now "
        f"{still_second['TagSet']!r} instead of generation='second'"
    )

    # --- Positive leg B: the same call with NO VersionId must address the CURRENT version and
    # say which one that was, rather than defaulting to the oldest or to all of them.
    cleared_current = s3.delete_object_tagging(Bucket=bucket, Key=key)
    assert cleared_current.get("VersionId") == v2, (
        f"the unversioned tag delete echoed VersionId {cleared_current.get('VersionId')!r}, want "
        f"the current version {v2!r}"
    )
    after_v2 = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=v2)
    assert after_v2["TagSet"] == [], (
        f"version {v2!r} still reports tags after the unversioned tag delete: "
        f"{after_v2['TagSet']!r}"
    )
    sibling_after_current = s3.get_object_tagging(Bucket=bucket, Key=key, VersionId=v1)
    assert sibling_after_current["TagSet"] == [{"Key": "generation", "Value": "requeued"}], (
        f"the unversioned tag delete also cleared non-current version {v1!r}, whose tag set is "
        f"now {sibling_after_current['TagSet']!r} instead of generation='requeued' — the "
        "unversioned form is deleting tags key-wide instead of addressing the current version"
    )

    # --- Invariants: a tag delete touches a sub-resource only. No ETag moved, no payload byte
    # changed, and the version list is exactly the two survivors with no marker invented.
    for vid, etag, body in ((v1, etag1, _BODY_V1), (v2, etag2, _BODY_V2)):
        head = s3.head_object(Bucket=bucket, Key=key, VersionId=vid)
        assert head["ETag"] == etag, (
            f"version {vid!r} reports ETag {head['ETag']!r} after its tags were deleted, want the "
            f"original {etag!r} — a tag delete must not rewrite the object"
        )
        assert head["ContentLength"] == len(body), (
            f"version {vid!r} reports ContentLength {head['ContentLength']!r}, want {len(body)}"
        )
        fetched = s3.get_object(Bucket=bucket, Key=key, VersionId=vid)
        payload = fetched["Body"].read()
        assert payload == body, (
            f"version {vid!r} no longer serves its payload byte-for-byte after its tag set was "
            f"deleted: got {len(payload)} bytes, want {len(body)}"
        )

    versions, markers = _all_versions(s3, bucket)
    assert sorted(v["VersionId"] for v in versions) == sorted([v1, v2]), (
        f"ListObjectVersions reports {sorted(v['VersionId'] for v in versions)!r}, want exactly "
        f"the two survivors {sorted([v1, v2])!r} — a tag delete must neither mint nor remove a "
        "version"
    )
    assert markers == [], (
        f"a tag delete invented delete markers: {markers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
