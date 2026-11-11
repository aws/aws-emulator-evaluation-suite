"""object-lock-subresource-puts-leave-the-object-body-and-versions-intact."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-lock-subresource-puts-leave-the-object-body-and-versions-intact"
GROUP = "object_lock"
SERVICES = ["s3"]

_KEY = "locked/report.csv"
_BODY = b"id,amount\n1,42\n2,17\n"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _release_and_delete_versions(s3, bucket: str) -> None:
    """Lift every legal hold, then delete every version under GOVERNANCE bypass."""
    pages = s3.get_paginator("list_object_versions")
    for page in pages.paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            s3.put_object_legal_hold(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"],
                                     LegalHold={"Status": "OFF"})
    for page in pages.paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"],
                             BypassGovernanceRetention=True)


def _versions(s3, bucket: str) -> tuple[list, list]:
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutObjectLegalHold and PutObjectRetention change only lock metadata: the object keeps its body,
    ETag, VersionId and ContentType, the key has one version and no delete marker, and HeadObject and
    both lock GETs report the hold ON and GOVERNANCE retention."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-lockmeta-")
    params: dict = {"Bucket": bucket, "ObjectLockEnabledForBucket": True}
    if ctx.region != "us-east-1":
        # us-east-1 must not be named as a LocationConstraint; every other region must be.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    ctx.on_cleanup(_teardown(lambda: _release_and_delete_versions(s3, bucket), "NoSuchBucket"))

    put = s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY, ContentType="text/csv")
    etag, version_id = put["ETag"], put["VersionId"]

    hold = s3.put_object_legal_hold(Bucket=bucket, Key=_KEY, LegalHold={"Status": "ON"})
    assert hold["ResponseMetadata"]["HTTPStatusCode"] == 200, hold["ResponseMetadata"]
    retain_until = (datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=1)).replace(microsecond=0)
    retention = s3.put_object_retention(
        Bucket=bucket, Key=_KEY,
        Retention={"Mode": "GOVERNANCE", "RetainUntilDate": retain_until},
    )
    assert retention["ResponseMetadata"]["HTTPStatusCode"] == 200, retention["ResponseMetadata"]

    got = s3.get_object(Bucket=bucket, Key=_KEY)
    body = got["Body"].read()
    assert body == _BODY, f"the current object body became {body!r}, expected {_BODY!r}"
    assert got["ETag"] == etag, f"the current ETag became {got['ETag']!r}, expected {etag!r}"
    assert got["VersionId"] == version_id, (
        f"the current version moved to a new VersionId after the lock PUTs "
        f"(same id: {got['VersionId'] == version_id})"
    )
    assert got["ContentType"] == "text/csv", f"ContentType became {got['ContentType']!r}"

    versions, markers = _versions(s3, bucket)
    assert [(v["Key"], v["VersionId"] == version_id, v["IsLatest"]) for v in versions] == [
        (_KEY, True, True)], (
        f"the bucket must hold exactly the one original version of {_KEY!r}, got "
        f"{[(v['Key'], v['IsLatest'], v['Size']) for v in versions]!r}"
    )
    assert markers == [], f"the lock PUTs created {len(markers)} delete marker(s)"

    head = s3.head_object(Bucket=bucket, Key=_KEY, VersionId=version_id)
    assert head.get("ObjectLockLegalHoldStatus") == "ON", head.get("ObjectLockLegalHoldStatus")
    assert head.get("ObjectLockMode") == "GOVERNANCE", head.get("ObjectLockMode")
    assert head.get("ObjectLockRetainUntilDate") == retain_until, (
        f"HeadObject reports retain-until {head.get('ObjectLockRetainUntilDate')!r}, "
        f"expected {retain_until!r}"
    )
    assert head["ContentLength"] == len(_BODY), head["ContentLength"]

    legal = s3.get_object_legal_hold(Bucket=bucket, Key=_KEY, VersionId=version_id)
    assert legal["LegalHold"] == {"Status": "ON"}, legal["LegalHold"]
    kept = s3.get_object_retention(Bucket=bucket, Key=_KEY, VersionId=version_id)["Retention"]
    assert kept == {"Mode": "GOVERNANCE", "RetainUntilDate": retain_until}, (
        f"GetObjectRetention returned {kept!r}, expected GOVERNANCE until {retain_until!r}"
    )

    # Lifting the hold is also metadata-only: the body and the version count stay put.
    s3.put_object_legal_hold(Bucket=bucket, Key=_KEY, VersionId=version_id,
                             LegalHold={"Status": "OFF"})
    lifted = s3.get_object_legal_hold(Bucket=bucket, Key=_KEY, VersionId=version_id)
    assert lifted["LegalHold"] == {"Status": "OFF"}, lifted["LegalHold"]
    again = s3.get_object(Bucket=bucket, Key=_KEY)
    assert again["Body"].read() == _BODY and again["VersionId"] == version_id, (
        "lifting the legal hold changed the current object"
    )
    versions, markers = _versions(s3, bucket)
    assert len(versions) == 1 and markers == [], (
        f"after lifting the hold the bucket holds {len(versions)} version(s) and "
        f"{len(markers)} delete marker(s); expected 1 and 0"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
