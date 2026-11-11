"""start-domain-export-token-reuse-with-changed-params-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-domain-export-token-reuse-with-changed-params-rejected"
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


def _error(fn) -> tuple[str, str]:
    """The ``(Code, Message)`` ``fn`` raises. An unexpected success raises too, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a StartDomainExport clientToken with a changed parameter is rejected with
    ConflictException, and the export the first call started is left exactly as it was.

    Reference: https://docs.aws.amazon.com/boto3/latest/reference/services/simpledbv2/client/start_domain_export.html
    """
    sdb = ctx.client("sdb")
    sdbv2 = ctx.client("simpledbv2")
    s3 = ctx.client("s3")

    export_arns: set[str] = set()

    domain = ctx.unique_name("sim2real-behav-sdbconf-")
    sdb.create_domain(DomainName=domain)
    ctx.on_cleanup(
        _teardown(
            lambda: (_await_exports_terminal(sdbv2, export_arns), sdb.delete_domain(DomainName=domain)),
            "NoSuchDomain",
        )
    )
    sdb.put_attributes(DomainName=domain, ItemName="item", Attributes=[{"Name": "k", "Value": "v"}])

    bucket = ctx.unique_name("sim2real-behav-sdbconf-").lower()
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

    token = ctx.unique_name("sim2real-behav-sdbconf-token-")
    first = sdbv2.start_domain_export(
        clientToken=token, domainName=domain, s3Bucket=bucket, s3KeyPrefix="original/"
    )
    export_arns.add(first["exportArn"])

    code, message = _error(
        lambda: sdbv2.start_domain_export(
            clientToken=token, domainName=domain, s3Bucket=bucket, s3KeyPrefix="changed/"
        )
    )
    assert code == "ConflictException", (
        f"expected reusing the clientToken with a changed s3KeyPrefix to raise "
        f"ConflictException, got {code!r}"
    )
    assert message == "Idempotent request failed due to parameter mismatch.", (
        f"expected the exact ConflictException message, got {message!r}"
    )

    unaffected = sdbv2.get_export(exportArn=first["exportArn"])
    assert unaffected["s3KeyPrefix"] == "original/", (
        f"the rejected retry mutated the original export's s3KeyPrefix to "
        f"{unaffected['s3KeyPrefix']!r}, expected it to stay 'original/'"
    )

    # Positive control: the same changed parameters succeed under a fresh token, proving the
    # rejection above came from the token reuse and not from the parameters themselves.
    retried = sdbv2.start_domain_export(domainName=domain, s3Bucket=bucket, s3KeyPrefix="changed/")
    export_arns.add(retried["exportArn"])
    assert retried["exportArn"] != first["exportArn"], (
        "a fresh token for the same 'changed' parameters should start a new export"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
