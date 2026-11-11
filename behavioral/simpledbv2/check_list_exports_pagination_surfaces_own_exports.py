"""list-exports-pagination-surfaces-own-exports."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-exports-pagination-surfaces-own-exports"
GROUP = "listing"
SERVICES = ["simpledbv2"]


#: Real exports take minutes to leave PENDING/IN_PROGRESS; neither the bucket nor the domain
#: can be torn down until every export this check started is terminal.
_EXPORT_SETTLE_TIMEOUT_S = 900.0


def _await_exports_terminal(sdbv2, export_arns, *, budget_s=_EXPORT_SETTLE_TIMEOUT_S, interval_s=10.0):
    deadline = time.monotonic() + budget_s
    pending = set(export_arns)
    while pending:
        pending = {
            arn
            for arn in pending
            if sdbv2.get_export(exportArn=arn)["exportStatus"] in ("PENDING", "IN_PROGRESS")
        }
        if pending:
            if time.monotonic() >= deadline:
                raise AssertionError(f"export(s) still not terminal after {budget_s}s: {pending!r}")
            time.sleep(interval_s)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _empty_and_delete_bucket(s3, bucket):
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExports pages a domain's exports instead of returning them all on the first page,
    and the full paginated walk still surfaces every export this check started.

    Reference: https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/ListingExports.html
    """
    sdb = ctx.client("sdb")
    sdbv2 = ctx.client("simpledbv2")
    s3 = ctx.client("s3")

    export_arns: set[str] = set()

    domain = ctx.unique_name("sim2real-behav-sdbpage-")
    sdb.create_domain(DomainName=domain)
    ctx.on_cleanup(
        _teardown(
            lambda: (_await_exports_terminal(sdbv2, export_arns), sdb.delete_domain(DomainName=domain)),
            "NoSuchDomain",
        )
    )
    sdb.put_attributes(DomainName=domain, ItemName="item", Attributes=[{"Name": "k", "Value": "v"}])

    bucket = ctx.unique_name("sim2real-behav-sdbpage-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(
        _teardown(
            lambda: (_await_exports_terminal(sdbv2, export_arns), _empty_and_delete_bucket(s3, bucket)),
            "NoSuchBucket",
        )
    )

    own_arns = {
        sdbv2.start_domain_export(domainName=domain, s3Bucket=bucket, s3KeyPrefix=f"p{i}/")[
            "exportArn"
        ]
        for i in range(3)
    }
    export_arns.update(own_arns)
    assert len(own_arns) == 3, f"expected 3 distinct exports, got {own_arns!r}"

    page_sizes = []
    collected: set[str] = set()
    pages = sdbv2.get_paginator("list_exports").paginate(
        domainName=domain, PaginationConfig={"PageSize": 1}
    )
    for page in pages:
        summaries = page["exportSummaries"]
        page_sizes.append(len(summaries))
        collected.update(e["exportArn"] for e in summaries)

    assert own_arns <= collected, (
        f"expected all of {own_arns!r} across the paginated walk, got {collected!r}"
    )
    assert all(size <= 1 for size in page_sizes), (
        f"a PageSize of 1 must bound every page, got page sizes {page_sizes!r}"
    )
    assert len(page_sizes) >= len(own_arns), (
        f"3 exports under a PageSize of 1 must span at least 3 pages, got {page_sizes!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
