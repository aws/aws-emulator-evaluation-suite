"""rrset-caa-record-resolves-overwrite-and-delete."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-caa-record-resolves-overwrite-and-delete"
GROUP = "resource-record-sets"
SERVICES = ["route53"]


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-caa").lower().replace("_", "-")
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


def _change(r53, zone_id, action, name, rtype, ttl, values):
    resp = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": action,
            "ResourceRecordSet": {
                "Name": name, "Type": rtype, "TTL": ttl,
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
        HostedZoneConfig={"Comment": "caa record round trip", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CAA record resolves with its quoted flags/tag/value intact, UPSERT replaces the whole
    value rather than merging it, and a deleted CAA record stops resolving.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    record_name = f"issue.{zone_name}"

    first_value = '0 issue "ca.example.test"'
    change_id = _change(r53, zone_id, "CREATE", record_name, "CAA", 300, [first_value])
    _wait_insync(r53, change_id)

    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="CAA")
    assert answer["ResponseCode"] == "NOERROR", (
        f"expected NOERROR for a CAA record just created, got {answer['ResponseCode']}: {answer}"
    )
    assert answer["RecordData"] == [first_value], (
        f"expected RecordData=[{first_value!r}], got {answer['RecordData']}"
    )

    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "CAA"]
    assert len(match) == 1, f"expected exactly one CAA record set, got {match}"
    assert match[0]["ResourceRecords"] == [{"Value": first_value}], (
        f"ListResourceRecordSets must echo the exact quoted value, got {match[0]['ResourceRecords']}"
    )

    # UPSERT with a different flags/tag/value triple replaces the whole record, it does not merge.
    second_value = '128 issuewild "ca2.example.test; account=100"'
    change_id = _change(r53, zone_id, "UPSERT", record_name, "CAA", 300, [second_value])
    _wait_insync(r53, change_id)

    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="CAA")
    assert answer["RecordData"] == [second_value], (
        f"UPSERT must replace the served CAA value; expected [{second_value!r}], got {answer['RecordData']}"
    )
    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "CAA"]
    assert match[0]["ResourceRecords"] == [{"Value": second_value}], (
        f"ListResourceRecordSets must show only the UPSERTed value, got {match[0]['ResourceRecords']}"
    )
    assert first_value not in [rr["Value"] for rr in match[0]["ResourceRecords"]], (
        "the pre-UPSERT value must not survive alongside the new one"
    )

    # DELETE: the name stops resolving as CAA and the record set is no longer listed.
    change_id = _change(r53, zone_id, "DELETE", record_name, "CAA", 300, [second_value])
    _wait_insync(r53, change_id)

    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType="CAA")
    assert answer["ResponseCode"] == "NXDOMAIN", (
        f"expected NXDOMAIN after deleting the only record at this name, got {answer['ResponseCode']}"
    )
    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "CAA"]
    assert match == [], f"the deleted CAA record set must no longer be listed, got {match}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
