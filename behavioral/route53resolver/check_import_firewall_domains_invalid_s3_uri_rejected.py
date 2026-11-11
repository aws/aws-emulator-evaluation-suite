"""import-firewall-domains-invalid-s3-uri-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-firewall-domains-invalid-s3-uri-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportFirewallDomains with a malformed S3 URI is rejected with ValidationException.

    A prior well-formed import sets a non-zero domain count that the rejected call must not change.
    """
    r53r = ctx.client("route53resolver")
    s3 = ctx.client("s3")

    list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-fdl-"),
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-fdl-")}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _delete_domain_list(r53r, list_id))

    bucket = _create_bucket(ctx, s3)
    control_domains = ["sim2real-import-control-a.example", "sim2real-import-control-b.example"]
    s3.put_object(Bucket=bucket, Key="domains.txt", Body="\n".join(control_domains).encode())

    # A successful well-formed import first shows the rejection below is about the URI.
    r53r.import_firewall_domains(
        FirewallDomainListId=list_id,
        Operation="REPLACE",
        DomainFileUrl=f"s3://{bucket}/domains.txt",
    )
    baseline_status = _poll_domain_list_status(
        r53r, list_id, {"COMPLETE", "COMPLETE_IMPORT_FAILED"}, timeout_s=120.0
    )
    assert baseline_status == "COMPLETE", f"positive-control import did not complete: {baseline_status!r}"
    baseline = r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]
    assert baseline["DomainCount"] == len(control_domains), (
        f"positive-control import landed {baseline['DomainCount']} domains, "
        f"expected {len(control_domains)}"
    )

    code, message = _error(
        lambda: r53r.import_firewall_domains(
            FirewallDomainListId=list_id,
            Operation="REPLACE",
            DomainFileUrl="not-a-valid-s3-uri",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "[RSLVR-02038] A valid S3 URL or S3 URI is required."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]
    assert unchanged["DomainCount"] == len(control_domains), (
        f"malformed import URI changed the domain count from {len(control_domains)} "
        f"to {unchanged['DomainCount']}"
    )
    assert unchanged["Status"] == "COMPLETE"


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _delete_domain_list(r53r, list_id: str) -> None:
    try:
        r53r.delete_firewall_domain_list(FirewallDomainListId=list_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-r53r-import-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself;
        # this is S3's own API quirk, not a region pin for this check.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _poll_domain_list_status(r53r, list_id: str, terminal_statuses, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]["Status"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"domain list {list_id} never reached {terminal_statuses} within {timeout_s}s, last status={status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
