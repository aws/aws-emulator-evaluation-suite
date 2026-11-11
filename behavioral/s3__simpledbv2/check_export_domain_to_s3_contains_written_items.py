"""export-domain-to-s3-contains-written-items."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-domain-to-s3-contains-written-items"
GROUP = "domain-export"
SERVICES = ["s3", "simpledbv2"]

_DEADLINE_S = 720.0
_POLL_S = 5.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Delete every object the export wrote into ``bucket``, then the bucket itself."""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SimpleDB domain exported to S3 writes every item's own attributes, byte-faithful.

    Reference: https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/USINGDomainExports.html
    """
    sdb = ctx.client("sdb")
    sdbv2 = ctx.client("simpledbv2")
    s3 = ctx.client("s3")

    domain = ctx.unique_name("sim2real-behav-sdbv2-domain-")
    bucket = ctx.unique_name("sim2real-behav-sdbv2-bucket-")

    sdb.create_domain(DomainName=domain)
    ctx.on_cleanup(_teardown(lambda: sdb.delete_domain(DomainName=domain)))

    items = {
        "item-widget": {"color": "blue"},
        "item-gadget": {"size": "large"},
    }
    for item_name, attrs in items.items():
        sdb.put_attributes(
            DomainName=domain,
            ItemName=item_name,
            Attributes=[{"Name": k, "Value": v, "Replace": True} for k, v in attrs.items()],
        )

    create_kwargs = {"Bucket": bucket}
    # S3 rejects an explicit LocationConstraint for its own default region, us-east-1.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    started = sdbv2.start_domain_export(
        domainName=domain,
        s3Bucket=bucket,
        s3KeyPrefix="exports/",
        s3SseAlgorithm="AES256",
        s3BucketOwner=ctx.account,
        clientToken=str(uuid.uuid4()),
    )
    export_arn = started["exportArn"]

    deadline = time.monotonic() + _DEADLINE_S
    export = sdbv2.get_export(exportArn=export_arn)
    while export["exportStatus"] not in ("SUCCEEDED", "FAILED"):
        assert time.monotonic() < deadline, (
            f"export stuck in {export['exportStatus']!r} past the {_DEADLINE_S}s deadline"
        )
        time.sleep(_POLL_S)
        export = sdbv2.get_export(exportArn=export_arn)

    assert export["exportStatus"] == "SUCCEEDED", (
        f"export ended {export['exportStatus']!r}: "
        f"{export.get('failureCode')!r} {export.get('failureMessage')!r}"
    )
    assert export["domainName"] == domain, (
        f"export reported domain {export['domainName']!r}, expected {domain!r}"
    )
    assert export["s3Bucket"] == bucket, (
        f"export reported bucket {export['s3Bucket']!r}, expected {bucket!r}"
    )

    paginator = s3.get_paginator("list_objects_v2")
    data_keys = [
        obj["Key"]
        for page in paginator.paginate(Bucket=bucket, Prefix="exports/")
        for obj in page.get("Contents", [])
        if "/data/" in obj["Key"]
    ]
    assert data_keys, f"export reported SUCCEEDED but wrote no data file under exports/ in {bucket!r}"

    exported_items: dict[str, dict[str, str]] = {}
    for key in data_keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        for row in json.loads(body):
            exported_items[row["itemName"]] = {
                attr["name"]: attr["values"][0] for attr in row["attributes"]
            }

    assert set(exported_items) == set(items), (
        f"exported items {sorted(exported_items)}, expected {sorted(items)}"
    )
    for item_name, attrs in items.items():
        assert exported_items[item_name] == attrs, (
            f"{item_name} exported as {exported_items[item_name]!r}, expected {attrs!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
