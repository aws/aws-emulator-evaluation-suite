"""rrset-ttl-boundary-min-and-max-accepted-and-served."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-ttl-boundary-min-and-max-accepted-and-served"
GROUP = "resource-record-sets"
SERVICES = ["route53"]

_MIN_TTL = 0
_MAX_TTL = 2147483647


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-ttl").lower().replace("_", "-")
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


def _change(r53, zone_id, action, name, ttl, value):
    resp = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{
            "Action": action,
            "ResourceRecordSet": {
                "Name": name, "Type": "A", "TTL": ttl,
                "ResourceRecords": [{"Value": value}],
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
        HostedZoneConfig={"Comment": "ttl boundary", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"]


def _rrset_of(r53, zone_id, name):
    rrsets = _list_all(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == name and r["Type"] == "A"]
    assert len(match) == 1, f"expected exactly one A record set at {name}, got {match}"
    return match[0]


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "dp:api", "plane:data", "plane:control")
def run(ctx) -> None:
    """TTL 0 and the maximum modelled TTL (2147483647) are both accepted, returned exactly by
    ListResourceRecordSets and the record still resolves through TestDNSAnswer at either bound.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)

    min_name = f"min-ttl.{zone_name}"
    change_id = _change(r53, zone_id, "CREATE", min_name, _MIN_TTL, "203.0.113.11")
    _wait_insync(r53, change_id)
    rrset = _rrset_of(r53, zone_id, min_name)
    assert rrset["TTL"] == _MIN_TTL, f"expected TTL {_MIN_TTL}, got {rrset['TTL']!r}"
    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=min_name, RecordType="A")
    assert answer["ResponseCode"] == "NOERROR", (
        f"a TTL={_MIN_TTL} record must still resolve, got {answer['ResponseCode']}: {answer}"
    )
    assert answer["RecordData"] == ["203.0.113.11"], answer

    max_name = f"max-ttl.{zone_name}"
    change_id = _change(r53, zone_id, "CREATE", max_name, _MAX_TTL, "203.0.113.12")
    _wait_insync(r53, change_id)
    rrset = _rrset_of(r53, zone_id, max_name)
    assert rrset["TTL"] == _MAX_TTL, f"expected TTL {_MAX_TTL}, got {rrset['TTL']!r}"
    answer = r53.test_dns_answer(HostedZoneId=zone_id, RecordName=max_name, RecordType="A")
    assert answer["ResponseCode"] == "NOERROR", (
        f"a TTL={_MAX_TTL} record must still resolve, got {answer['ResponseCode']}: {answer}"
    )
    assert answer["RecordData"] == ["203.0.113.12"], answer

    # UPSERT from the maximum TTL down to the minimum, on the same name: the bound is per-write,
    # not sticky to the record.
    change_id = _change(r53, zone_id, "UPSERT", max_name, _MIN_TTL, "203.0.113.12")
    _wait_insync(r53, change_id)
    rrset = _rrset_of(r53, zone_id, max_name)
    assert rrset["TTL"] == _MIN_TTL, (
        f"UPSERT must move the record from the max TTL to {_MIN_TTL}, got {rrset['TTL']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
