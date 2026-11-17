"""rrset-simple-routing-serves-every-value-in-random-order."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-simple-routing-serves-every-value-in-random-order"
GROUP = "resource-record-sets"
SERVICES = ["route53"]


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-mv").lower().replace("_", "-")
    return f"{raw}.example.test."


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


def _wait_insync(r53, change_id):
    return _poll(
        lambda: r53.get_change(Id=change_id),
        lambda resp: resp["ChangeInfo"]["Status"] == "INSYNC",
        timeout_s=90.0, interval_s=2.0, what=f"change {change_id} to reach INSYNC",
    )


def _change(r53, zone_id, action, name, values):
    resp = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": action,
            "ResourceRecordSet": {
                "Name": name, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": v} for v in values],
            },
        }]},
    )
    return resp["ChangeInfo"]["Id"]


def _list_all(r53, zone_id):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _empty_and_delete_zone(r53, zone_id):
    for rrs in _list_all(r53, zone_id):
        if rrs["Type"] in ("NS", "SOA"):
            continue
        try:
            r53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidChangeBatch", "NoSuchHostedZone"):
                raise
    try:
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _create_zone(ctx, r53):
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "simple routing multivalue", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"]


def _resolved_set(r53, zone_id, record_name):
    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="A")
    assert answer["ResponseCode"] == "NOERROR", (
        f"expected NOERROR resolving {record_name}, got {answer['ResponseCode']}: {answer}"
    )
    return answer["RecordData"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data", "plane:control")
def run(ctx) -> None:
    """A simple-routing A record with several values is listed in the exact order submitted, but
    resolving it serves every one of those values -- none dropped, none duplicated -- regardless
    of the order TestDNSAnswer happens to return them in, and UPSERT replaces the whole set.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy-simple.html
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    record_name = f"multi.{zone_name}"

    # Deliberately NOT sorted numerically or lexicographically, so echoing a sort would fail.
    first_values = ["203.0.113.40", "203.0.113.10", "203.0.113.50", "203.0.113.5", "203.0.113.30"]
    change_id = _change(r53, zone_id, "CREATE", record_name, first_values)
    _wait_insync(r53, change_id)

    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "A"]
    assert len(match) == 1, f"expected exactly one A record set at {record_name}, got {match}"
    observed = [rr["Value"] for rr in match[0]["ResourceRecords"]]
    assert observed == first_values, (
        f"ListResourceRecordSets must echo the submitted order exactly; expected {first_values}, "
        f"got {observed}"
    )
    assert sorted(observed) != observed, (
        "the fixture stopped discriminating submission order from a sorted order"
    )

    resolved = _resolved_set(r53, zone_id, record_name)
    assert sorted(resolved) == sorted(first_values), (
        f"TestDNSAnswer must serve every submitted value exactly once; expected the set "
        f"{sorted(first_values)}, got {sorted(resolved)}"
    )
    assert len(resolved) == len(first_values), (
        f"expected {len(first_values)} values with none dropped or duplicated, got {resolved}"
    )

    # UPSERT with an entirely different five-value set: it replaces the record, not merges it.
    second_values = ["198.51.100.21", "198.51.100.22", "198.51.100.23", "198.51.100.24", "198.51.100.25"]
    change_id = _change(r53, zone_id, "UPSERT", record_name, second_values)
    _wait_insync(r53, change_id)

    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "A"]
    observed = [rr["Value"] for rr in match[0]["ResourceRecords"]]
    assert observed == second_values, (
        f"UPSERT must replace the record set with exactly the new values in the order "
        f"submitted; expected {second_values}, got {observed}"
    )

    resolved = _resolved_set(r53, zone_id, record_name)
    assert sorted(resolved) == sorted(second_values), (
        f"after UPSERT, TestDNSAnswer must serve exactly the new set; expected "
        f"{sorted(second_values)}, got {sorted(resolved)}"
    )
    assert not (set(resolved) & set(first_values)), (
        f"none of the pre-UPSERT values may survive; resolved={resolved}, old={first_values}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
