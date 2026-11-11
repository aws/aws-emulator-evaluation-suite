"""import-firewall-domains-conflict-while-in-progress."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-firewall-domains-conflict-while-in-progress"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]

# Domains per account quota is 100,000 (each REPLACE import fully supersedes
# the list's current contents, so a single list never accumulates across
# attempts). https://docs.aws.amazon.com/general/latest/gr/r53.html
_ATTEMPT_SIZES = (40_000, 90_000)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second ImportFirewallDomains while the list is IMPORTING returns ConflictException.

    The running import's outcome is untouched, and a later import on the settled list succeeds.
    """
    s3 = ctx.client("s3")
    r53r = ctx.client("route53resolver")

    bucket_name = _create_bucket(ctx, s3)
    domain_list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-fdl-cr-"),
        Name=ctx.unique_name("sim2real-fdl-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id))

    conflict = None
    first_attempt_count = None
    winning_size = None
    for attempt, size in enumerate(_ATTEMPT_SIZES):
        key = f"import-attempt-{attempt}.txt"
        _upload_domain_file(s3, bucket_name, key, size)
        file_url = f"s3://{bucket_name}/{key}"

        started = r53r.import_firewall_domains(
            FirewallDomainListId=domain_list_id, Operation="REPLACE", DomainFileUrl=file_url
        )
        assert started["Status"] in ("IMPORTING", "COMPLETE"), (
            f"expected the import to start IMPORTING or finish COMPLETE, got {started['Status']!r}"
        )
        # Only race while a read confirms the list is still IMPORTING; a list that already
        # settled is retried with a larger file instead.
        held = r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"]
        if held == "IMPORTING":
            try:
                r53r.import_firewall_domains(
                    FirewallDomainListId=domain_list_id, Operation="REPLACE", DomainFileUrl=file_url
                )
            except ClientError as exc:
                conflict = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        _poll_until(
            lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
                "FirewallDomainList"
            ]["Status"],
            lambda s: s in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
            timeout_s=600,
            interval_s=5,
        )
        if conflict is not None:
            winning_size = size
            first_attempt_count = r53r.get_firewall_domain_list(
                FirewallDomainListId=domain_list_id
            )["FirewallDomainList"]["DomainCount"]
            break

    assert conflict is not None, (
        "never held a still-IMPORTING list to race a conflicting import against"
    )
    code, message = conflict
    assert code == "ConflictException", f"expected ConflictException, got {code!r} ({message!r})"
    expected = (
        f'[RSLVR-02305] The DNS Firewall domain list is in importing status: "{domain_list_id}". '
        "Try again after the import completes."
    )
    assert _without_trace_id(message) == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected call did not queue or blend anything: the count is the running import's.
    assert first_attempt_count == winning_size

    small_key = "import-followup.txt"
    _upload_domain_file(s3, bucket_name, small_key, 3)
    followup = r53r.import_firewall_domains(
        FirewallDomainListId=domain_list_id,
        Operation="REPLACE",
        DomainFileUrl=f"s3://{bucket_name}/{small_key}",
    )
    assert followup["Status"] in ("IMPORTING", "COMPLETE"), (
        f"positive control: import against the now-idle list should start or finish, "
        f"got {followup['Status']!r}"
    )
    final_status = _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"],
        lambda s: s in ("COMPLETE", "COMPLETE_IMPORT_FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert final_status == "COMPLETE"
    assert (
        r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)["FirewallDomainList"][
            "DomainCount"
        ]
        == 3
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_bucket(ctx, s3):
    bucket_name = ctx.unique_name("sim2real-r53r-import-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    return bucket_name


def _empty_and_delete_bucket(s3, bucket_name):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _upload_domain_file(s3, bucket_name, key, count):
    body = "\n".join(f"host{i}.sim2real-import-test" for i in range(count)).encode("utf-8")
    s3.put_object(Bucket=bucket_name, Key=key, Body=body)


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
