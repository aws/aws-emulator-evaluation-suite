"""deep-s3-storage-class-lifecycle-transition-invalid-target-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-lifecycle-transition-invalid-target-rejected"
GROUP = "storage-class"
SERVICES = ["s3"]

_BASELINE = [{
    "ID": "baseline-to-glacier",
    "Status": "Enabled",
    "Filter": {"Prefix": "cold/"},
    "Transitions": [{"Days": 30, "StorageClass": "GLACIER"}],
}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketLifecycleConfiguration with a Transition to STANDARD is refused with InvalidArgument and
    its exact message, and the rules stored before it read back unchanged: a refused PUT is atomic."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-lt-")

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    # Positive control: a valid transition target is accepted and stored.
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": _BASELINE})
    stored = _poll_rules(s3, bucket, _canon(_BASELINE))
    assert stored == _canon(_BASELINE), f"baseline read back as {stored!r}"

    bad = [{
        "ID": "to-standard",
        "Status": "Enabled",
        "Filter": {"Prefix": "cold/"},
        "Transitions": [{"Days": 30, "StorageClass": "STANDARD"}],
    }]
    err = _client_error(lambda: s3.put_bucket_lifecycle_configuration(
        Bucket=bucket, LifecycleConfiguration={"Rules": bad},
    ))
    assert err.get("Code") == "InvalidArgument", f"Transition to STANDARD returned {err!r}, expected InvalidArgument"
    assert err.get("Message") == "Invalid target Storage class for Transition action", err

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
