"""deep-s3-storage-class-lifecycle-transition-ia-to-glacier-gap-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-lifecycle-transition-ia-to-glacier-gap-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]

_BASELINE = [{
    "ID": "ia-30-glacier-60",
    "Status": "Enabled",
    "Filter": {"Prefix": "tiered/"},
    "Transitions": [
        {"Days": 30, "StorageClass": "STANDARD_IA"},
        {"Days": 60, "StorageClass": "GLACIER"},
    ],
}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketLifecycleConfiguration accepts STANDARD_IA@30 -> GLACIER@60 and refuses STANDARD_IA@30
    -> GLACIER@40 with InvalidArgument and its exact message (STANDARD_IA's 30-day minimum), leaving the
    stored rules unchanged."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-lg-")

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": _BASELINE})
    stored = _poll_rules(s3, bucket, _canon(_BASELINE))
    assert stored == _canon(_BASELINE), f"30-day-gap baseline read back as {stored!r}"

    short_gap = [{
        "ID": "ia-30-glacier-40",
        "Status": "Enabled",
        "Filter": {"Prefix": "tiered/"},
        "Transitions": [
            {"Days": 30, "StorageClass": "STANDARD_IA"},
            {"Days": 40, "StorageClass": "GLACIER"},
        ],
    }]
    err = _client_error(lambda: s3.put_bucket_lifecycle_configuration(
        Bucket=bucket, LifecycleConfiguration={"Rules": short_gap},
    ))
    assert err.get("Code") == "InvalidArgument", f"STANDARD_IA@30 -> GLACIER@40 returned {err!r}, expected InvalidArgument"
    assert err.get("Message") == "'Days' in the 'Transition' action for StorageClass 'GLACIER' for filter '(prefix=tiered/)' must be 30 days more than 'filter '(prefix=tiered/)'' in the 'Transition' action for StorageClass 'STANDARD_IA'", err

    after = _rules(s3, bucket)
    assert after == _canon(_BASELINE), f"a refused PUT changed the stored rules to {after!r}"


def _canon(rules: list) -> list:
    out = []
    for r in rules:
        out.append({
            "ID": r["ID"], "Status": r["Status"], "Filter": r.get("Filter"),
            "Transitions": sorted(r.get("Transitions", []), key=lambda t: t["Days"]),
        })
    return sorted(out, key=lambda r: r["ID"])


def _rules(s3, bucket: str) -> list:
    return _canon(s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"])


def _poll_rules(s3, bucket: str, expected: list, attempts: int = 20, delay: float = 3.0):
    """Lifecycle configuration propagates eventually: poll for the stored value, never time it."""
    seen = None
    for _ in range(attempts):
        try:
            seen = _rules(s3, bucket)
        except ClientError as exc:
            seen = exc.response.get("Error", {}).get("Code")
        if seen == expected:
            return seen
        time.sleep(delay)
    return seen


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"])
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
