"""import-firewall-domains-conflict-while-in-progress-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-firewall-domains-conflict-while-in-progress-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second ImportFirewallDomains while the first is still importing fails with ConflictException;
    the first import completes with exactly its domains, and a later import on the idle list succeeds.
    """
    r53r = ctx.client("route53resolver")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-r53fw").lower().replace("_", "-")
    _create_bucket(ctx, bucket)

    # Large enough that the asynchronous import is still IMPORTING when the second call lands.
    domain_count = 3000
    key = "domains.txt"
    body = "\n".join(f"sim2real-behav-{i}.example.com" for i in range(domain_count)).encode()
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    domain_url = f"s3://{bucket}/{key}"

    domain_list = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
    )["FirewallDomainList"]
    list_id = domain_list["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=list_id))

    code, message = _second_import_while_importing(ctx, r53r, list_id, domain_url)
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = (
        f'[RSLVR-02305] The DNS Firewall domain list is in importing status: "{list_id}". '
        "Try again after the import completes."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    final = _wait_for_domain_list_status(ctx, list_id, {"COMPLETE", "COMPLETE_IMPORT_FAILED"})
    assert final["Status"] == "COMPLETE", f"first import did not complete cleanly: {final}"
    assert final["DomainCount"] == domain_count, (
        f"expected exactly {domain_count} domains from the single successful import, "
        f"got {final['DomainCount']} (rejected second call must not have partially applied)"
    )

    # Positive control: once idle, a further import against the same list succeeds.
    second = r53r.import_firewall_domains(
        FirewallDomainListId=list_id, Operation="REPLACE", DomainFileUrl=domain_url
    )
    assert second["Status"] in ("IMPORTING", "COMPLETE")
    final2 = _wait_for_domain_list_status(ctx, list_id, {"COMPLETE", "COMPLETE_IMPORT_FAILED"})
    assert final2["Status"] == "COMPLETE"


_TRACE_ID = ' Trace Id: "'


def _code_message(exc: ClientError):
    """(Error.Code, Error.Message) of *exc*, with the per-request X-Ray trace id suffix removed."""
    err = exc.response.get("Error", {})
    message = err.get("Message", "")
    head, sep, _ = message.rpartition(_TRACE_ID)
    return err.get("Code"), (head if sep and message.endswith('"') else message)


#: Import pairs tried for a second ImportFirewallDomains that lands while the first still imports.
_IMPORT_WINDOW_ATTEMPTS = 3


def _second_import_while_importing(ctx, r53r, list_id, domain_url):
    """A REPLACE import, then the identical import at once; return the second call's refusal
    ``(code, message)``. A second call accepted means the first import had already completed, so
    the list settles and the pair runs again, up to the cap."""
    accepted = []
    for _ in range(_IMPORT_WINDOW_ATTEMPTS):
        first = r53r.import_firewall_domains(
            FirewallDomainListId=list_id, Operation="REPLACE", DomainFileUrl=domain_url
        )
        assert first["Status"] in ("IMPORTING", "COMPLETE")
        try:
            second = r53r.import_firewall_domains(
                FirewallDomainListId=list_id, Operation="REPLACE", DomainFileUrl=domain_url
            )
        except ClientError as exc:
            return _code_message(exc)
        accepted.append((first["Status"], second["Status"]))
        _wait_for_domain_list_status(ctx, list_id, {"COMPLETE", "COMPLETE_IMPORT_FAILED"})
    raise AssertionError(
        f"a second ImportFirewallDomains issued right after the first was accepted every time "
        f"(first, second status per round: {accepted}), so it never landed while one was importing"
    )


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _wait_for_domain_list_status(ctx, list_id, terminal_statuses, timeout_s=180.0):
    r53r = ctx.client("route53resolver")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]
        if last["Status"] in terminal_statuses:
            return last
        time.sleep(2.0)
    raise AssertionError(f"domain list {list_id} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
