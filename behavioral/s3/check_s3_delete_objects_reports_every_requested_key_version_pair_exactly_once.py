"""s3-delete-objects-reports-every-requested-key-version-pair-exactly-once."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-delete-objects-reports-every-requested-key-version-pair-exactly-once"
GROUP = 'error-semantics'
SERVICES = ['s3']

_V1 = b"v1-bytes"
_V2 = b"v2-bytes-and-this-version-must-survive-the-batch"
_BOGUS_VERSION = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


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


def _versions_for_key(client, bucket, key):
    """Return every version id currently listed for one key (versions + delete markers)."""
    found = []
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            if o["Key"] == key:
                found.append(o["VersionId"])
    return found


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects reports each requested (Key, VersionId) pair exactly once, with its id echoed.

    A live version lands in Deleted[], a non-existent one in Errors[] as NoSuchVersion; only the
    named version is removed, no delete marker appears, and the current bytes are unchanged.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert status == "Enabled", f"versioning did not take effect: Status is {status!r}"

    key = "batch/versioned.bin"
    first = s3.put_object(Bucket=bucket, Key=key, Body=_V1)
    doomed_version = first.get("VersionId")
    assert doomed_version, (
        f"a versioning-enabled bucket must return a VersionId from PutObject, got "
        f"{doomed_version!r} -- without one this check cannot name a live version to delete"
    )
    second = s3.put_object(Bucket=bucket, Key=key, Body=_V2)
    surviving_version = second.get("VersionId")
    assert surviving_version and surviving_version != doomed_version, (
        f"the overwrite must produce a distinct VersionId, got {surviving_version!r} against "
        f"{doomed_version!r}"
    )

    baseline = _versions_for_key(s3, bucket, key)
    assert sorted(baseline) == sorted([doomed_version, surviving_version]), (
        f"before the batch the key must hold exactly the two versions just written "
        f"{sorted([doomed_version, surviving_version])!r}, ListObjectVersions reports "
        f"{sorted(baseline)!r} -- unless the doomed version is really there first, a later "
        f"'it is gone' assertion passes trivially against a store that never kept it"
    )

    requested = [
        {"Key": key, "VersionId": doomed_version},
        {"Key": key, "VersionId": _BOGUS_VERSION},
    ]
    resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": list(requested)})
    deleted = [(d.get("Key"), d.get("VersionId")) for d in resp.get("Deleted", [])]
    errored = [(e.get("Key"), e.get("VersionId")) for e in resp.get("Errors", [])]
    reported = deleted + errored

    assert len(reported) == len(requested), (
        f"DeleteObjects must report every requested entry: asked for {len(requested)} entries, "
        f"got {len(reported)} (Deleted={deleted!r}, Errors={errored!r})"
    )

    for entry in requested:
        pair = (entry["Key"], entry["VersionId"])
        occurrences = reported.count(pair)
        assert occurrences == 1, (
            f"requested entry {pair!r} must be reported exactly once with its version id echoed "
            f"back, it appears {occurrences} time(s) (Deleted={deleted!r}, Errors={errored!r})"
        )

    both_sides = sorted(set(deleted) & set(errored))
    assert both_sides == [], (
        f"Deleted[] and Errors[] must be disjoint, these pairs appear on both sides: "
        f"{both_sides!r}"
    )

    doomed_pair = (key, doomed_version)
    bogus_pair = (key, _BOGUS_VERSION)
    assert deleted.count(doomed_pair) == 1, (
        f"the live version named in the batch must be reported on the SUCCESS side exactly "
        f"once: {doomed_pair!r} appears {deleted.count(doomed_pair)} time(s) in "
        f"Deleted={deleted!r} (Errors={errored!r})"
    )
    assert errored.count(bogus_pair) == 1, (
        f"the non-existent version named in the batch must be reported on the ERROR side "
        f"exactly once rather than laundered into a success: {bogus_pair!r} appears "
        f"{errored.count(bogus_pair)} time(s) in Errors={errored!r} (Deleted={deleted!r})"
    )

    bogus_error = next(
        e for e in resp.get("Errors", []) if (e.get("Key"), e.get("VersionId")) == bogus_pair
    )
    bogus_code = bogus_error.get("Code")
    bogus_message = bogus_error.get("Message")
    assert bogus_code == "NoSuchVersion", (
        f"expected Errors[] Code 'NoSuchVersion' for the non-existent version {bogus_pair!r}, "
        f"got {bogus_code!r} in {bogus_error!r}"
    )
    assert bogus_message == "The specified version does not exist.", (
        f"expected Errors[] Message 'The specified version does not exist.' for the non-existent "
        f"version {bogus_pair!r}, got {bogus_message!r} in {bogus_error!r}"
    )

    remaining = _versions_for_key(s3, bucket, key)
    assert sorted(remaining) == [surviving_version], (
        f"after the batch the key must hold exactly the one surviving version "
        f"{[surviving_version]!r} (deleted: {doomed_version!r}), ListObjectVersions reports "
        f"{sorted(remaining)!r} -- a version-pinned delete must remove only the version it names, "
        f"without inventing a delete marker or stranding an extra version"
    )
    current = s3.get_object(Bucket=bucket, Key=key)
    current_body = current["Body"].read()
    assert current_body == _V2, (
        f"the current version's bytes changed during the batch delete: got {current_body!r}, "
        f"want {_V2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
