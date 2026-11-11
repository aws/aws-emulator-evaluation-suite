"""export-lifecycle-lands-verified-data-in-s3."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-lifecycle-lands-verified-data-in-s3"
GROUP = "export_lifecycle"
SERVICES = ["simpledbv2"]

#: A real export takes minutes to leave PENDING/IN_PROGRESS.
_EXPORT_TERMINAL_TIMEOUT_S = 1200.0


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_domain_when_exports_settle(sdb, domain, *, budget_s=900.0, interval_s=15.0):
    """Delete a domain, retrying while AWS blocks it on a still-PENDING/IN_PROGRESS export."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            sdb.delete_domain(DomainName=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchDomain":
                return
            if code != "DeleteConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _make_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-sdbexp-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _empty_and_delete():
        while True:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if not objs:
                break
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_teardown(_empty_and_delete, "NoSuchBucket"))
    return bucket


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartDomainExport writes the domain's real items to S3 under the service's own
    AWSSimpleDB/<exportId>/<domainName> layout, and the export's advertised
    exportManifest field does not point at that object -- or any object the export wrote.

    Reference: https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/WorkingWithDomainsExport.html
    """
    sdb = ctx.client("sdb")
    sdbv2 = ctx.client("simpledbv2")
    s3 = ctx.client("s3")

    domain = ctx.unique_name("sim2real-behav-sdbexp-")
    sdb.create_domain(DomainName=domain)
    ctx.on_cleanup(lambda: _delete_domain_when_exports_settle(sdb, domain))

    items = {
        "widget-1": [{"Name": "color", "Value": "red"}],
        "widget-2": [{"Name": "color", "Value": "blue"}],
    }
    for item_name, attrs in items.items():
        sdb.put_attributes(DomainName=domain, ItemName=item_name, Attributes=attrs)

    bucket = _make_bucket(ctx, s3)
    prefix = "exports/"

    start = sdbv2.start_domain_export(domainName=domain, s3Bucket=bucket, s3KeyPrefix=prefix)
    export_arn = start["exportArn"]
    assert export_arn.startswith(f"arn:aws:sdb:{ctx.region}:{ctx.account}:domain/{domain}/export/"), (
        f"expected exportArn under domain {domain!r} in account {ctx.account}, got {export_arn!r}"
    )

    terminal = _poll_until(
        lambda: sdbv2.get_export(exportArn=export_arn),
        lambda g: g["exportStatus"] not in ("PENDING", "IN_PROGRESS"),
        timeout_s=_EXPORT_TERMINAL_TIMEOUT_S,
        interval_s=15.0,
        description="export reached a terminal state",
    )
    assert terminal["exportStatus"] == "SUCCEEDED", (
        f"expected the export to reach SUCCEEDED, got {terminal['exportStatus']!r}: "
        f"{terminal.get('failureCode')}/{terminal.get('failureMessage')}"
    )

    # GetExport's itemsCount is a flat 100 regardless of how many items the domain actually held,
    # even though the model documents it as "Total number of exported items."
    assert terminal["itemsCount"] == 100, (
        f"expected GetExport.itemsCount to be the fixed placeholder 100 regardless of the "
        f"domain's real {len(items)} items, got {terminal['itemsCount']!r}"
    )

    # The exportManifest field is itself unreliable: it never resolves to a real S3 object (a
    # different namespace segment and a swapped domain/id order from what the export actually
    # wrote), so a check must locate the manifest structurally rather than trust the field.
    manifest_field = terminal["exportManifest"]
    code = None
    try:
        s3.head_object(Bucket=bucket, Key=manifest_field)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    assert code == "404", (
        f"expected GetExport.exportManifest {manifest_field!r} to NOT resolve to a real S3 "
        f"object (a known AWS defect), but head_object returned success or a different error"
    )

    listing = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    keys = [o["Key"] for o in listing.get("Contents", [])]
    manifest_keys = [k for k in keys if k.endswith("manifest-summary.json")]
    assert len(manifest_keys) == 1, f"expected exactly one manifest-summary.json, found {keys!r}"
    manifest_key = manifest_keys[0]
    assert "/AWSSimpleDB/" in manifest_key, (
        f"expected the real export layout to carry /AWSSimpleDB/, got {manifest_key!r}"
    )

    manifest = json.loads(s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read())
    assert manifest["domainName"] == domain, (
        f"expected manifest-summary domainName {domain!r}, got {manifest['domainName']!r}"
    )
    assert manifest["itemsCount"] == len(items), (
        f"expected the manifest's own itemsCount to be the real {len(items)}, "
        f"got {manifest['itemsCount']!r} -- unlike GetExport, the manifest reflects reality"
    )

    files_key = manifest_key.replace("manifest-summary.json", "manifest-file.json")
    assert files_key in keys, f"expected a manifest-file.json beside {manifest_key!r}, got {keys!r}"
    file_entries = json.loads(s3.get_object(Bucket=bucket, Key=files_key)["Body"].read())
    data_keys = [e["dataFileS3Key"] for e in file_entries]
    assert data_keys and all(k in keys for k in data_keys), (
        f"manifest-file.json names data files {data_keys!r} that were not written: {keys!r}"
    )

    exported_items: dict[str, dict[str, str]] = {}
    for data_key in data_keys:
        records = json.loads(s3.get_object(Bucket=bucket, Key=data_key)["Body"].read())
        for record in records:
            exported_items[record["itemName"]] = {
                a["name"]: a["values"][0] for a in record["attributes"]
            }

    expected = {name: {a["Name"]: a["Value"] for a in attrs} for name, attrs in items.items()}
    assert exported_items == expected, (
        f"exported item content {exported_items!r} does not match what was put {expected!r}"
    )

    found = sdbv2.get_paginator("list_exports").paginate(domainName=domain)
    arns = {e["exportArn"] for page in found for e in page["exportSummaries"]}
    assert export_arn in arns, f"expected {export_arn} in ListExports for {domain!r}, got {arns!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
