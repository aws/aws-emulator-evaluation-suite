"""start-domain-export-idempotent-retry-returns-same-export."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-domain-export-idempotent-retry-returns-same-export"
GROUP = "idempotency"
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
    """A repeated StartDomainExport call carrying the same clientToken and the same other
    parameters returns the identical export rather than starting a second one, and a call
    with a fresh token starts a genuinely new export.

    Reference: https://docs.aws.amazon.com/boto3/latest/reference/services/simpledbv2/client/start_domain_export.html
    """
    sdb = ctx.client("sdb")
    sdbv2 = ctx.client("simpledbv2")
    s3 = ctx.client("s3")

    export_arns: set[str] = set()

    domain = ctx.unique_name("sim2real-behav-sdbidem-")
    sdb.create_domain(DomainName=domain)
    ctx.on_cleanup(
        _teardown(
            lambda: (_await_exports_terminal(sdbv2, export_arns), sdb.delete_domain(DomainName=domain)),
            "NoSuchDomain",
        )
    )
    sdb.put_attributes(DomainName=domain, ItemName="item", Attributes=[{"Name": "k", "Value": "v"}])

    bucket = ctx.unique_name("sim2real-behav-sdbidem-").lower()
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

    token = ctx.unique_name("sim2real-behav-sdbidem-token-")
    first = sdbv2.start_domain_export(
        clientToken=token, domainName=domain, s3Bucket=bucket, s3KeyPrefix="first/"
    )
    export_arns.add(first["exportArn"])
    repeat = sdbv2.start_domain_export(
        clientToken=token, domainName=domain, s3Bucket=bucket, s3KeyPrefix="first/"
    )
    assert repeat["exportArn"] == first["exportArn"], (
        f"a retry with the same clientToken started a different export: "
        f"{first['exportArn']!r} then {repeat['exportArn']!r}"
    )
    assert repeat["requestedAt"] == first["requestedAt"], (
        f"a retry with the same clientToken changed requestedAt: "
        f"{first['requestedAt']!r} then {repeat['requestedAt']!r}"
    )

    distinct = sdbv2.start_domain_export(domainName=domain, s3Bucket=bucket, s3KeyPrefix="second/")
    export_arns.add(distinct["exportArn"])
    assert distinct["exportArn"] != first["exportArn"], (
        "a call with a fresh clientToken must start a genuinely new export, "
        f"but it returned the same exportArn {first['exportArn']!r}"
    )

    pages = sdbv2.get_paginator("list_exports").paginate(domainName=domain)
    arns = {e["exportArn"] for page in pages for e in page["exportSummaries"]}
    assert {first["exportArn"], distinct["exportArn"]} <= arns, (
        f"expected both {first['exportArn']!r} and {distinct['exportArn']!r} in ListExports, "
        f"got {arns!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
