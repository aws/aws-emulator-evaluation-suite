"""repeated-client-token-with-different-params-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "repeated-client-token-with-different-params-rejected"
GROUP = "idempotency"
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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a StartDomainExport client token with changed parameters is a ConflictException,
    and the export the first, matching call started is left running, not duplicated."""
    sdb = ctx.client("sdb")
    sdbv2 = ctx.client("simpledbv2")
    s3 = ctx.client("s3")

    domain = ctx.unique_name("sim2real-behav-sdbv2-domain-")
    bucket = ctx.unique_name("sim2real-behav-sdbv2-bucket-")

    sdb.create_domain(DomainName=domain)
    ctx.on_cleanup(_teardown(lambda: sdb.delete_domain(DomainName=domain)))
    sdb.put_attributes(
        DomainName=domain,
        ItemName="item-widget",
        Attributes=[{"Name": "color", "Value": "blue", "Replace": True}],
    )

    create_kwargs = {"Bucket": bucket}
    # S3 rejects an explicit LocationConstraint for its own default region, us-east-1.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    token = str(uuid.uuid4())
    started = sdbv2.start_domain_export(
        domainName=domain, s3Bucket=bucket, s3KeyPrefix="exports/", clientToken=token
    )
    export_arn = started["exportArn"]

    # Positive control: the exact same request, same token, is the idempotent no-op AWS documents.
    repeat = sdbv2.start_domain_export(
        domainName=domain, s3Bucket=bucket, s3KeyPrefix="exports/", clientToken=token
    )
    assert repeat["exportArn"] == export_arn, (
        f"an identical retry with the same token minted a new export {repeat['exportArn']!r}, "
        f"expected the original {export_arn!r}"
    )

    code, message = _error(
        lambda: sdbv2.start_domain_export(
            domainName=domain, s3Bucket=bucket, s3KeyPrefix="exports/changed/", clientToken=token
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == "Idempotent request failed due to parameter mismatch.", (
        f"unexpected message {message!r}"
    )

    summaries = sdbv2.list_exports(domainName=domain)["exportSummaries"]
    arns = [s["exportArn"] for s in summaries]
    assert arns == [export_arn], (
        f"domain {domain!r} shows exports {arns!r}, expected only the original {export_arn!r}"
    )

    deadline = time.monotonic() + _DEADLINE_S
    export = sdbv2.get_export(exportArn=export_arn)
    while export["exportStatus"] not in ("SUCCEEDED", "FAILED"):
        assert time.monotonic() < deadline, (
            f"export stuck in {export['exportStatus']!r} past the {_DEADLINE_S}s deadline"
        )
        time.sleep(_POLL_S)
        export = sdbv2.get_export(exportArn=export_arn)
    assert export["exportStatus"] == "SUCCEEDED", (
        f"the original export, left running by the rejected retry, ended "
        f"{export['exportStatus']!r}: {export.get('failureCode')!r} {export.get('failureMessage')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
