"""test-dns-answer-evaluates-weighted-routing."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "test-dns-answer-evaluates-weighted-routing"
GROUP = 'resource-record-sets'
SERVICES = ['route53']


# Teardown deletes alias record sets first (a same-zone alias blocks its target's deletion) and
# raises on failure: DeleteHostedZone fails with HostedZoneNotEmpty while any non-NS/SOA record
# set remains, and a leaked zone keeps billing. It waits on ListResourceRecordSets state rather
# than INSYNC, because HostedZoneNotEmpty is evaluated against API state.
# Zone names use `.test`, an RFC 2606 reserved TLD (AWS reserves example.com/.org/.net).

def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    return f"{raw}.example.test."


def _poll(probe, done, *, timeout_s=60.0, interval_s=2.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last={last!r}"
            )
        time.sleep(interval_s)


def _change(r53, zone_id, changes, tries=4):
    """Submit a ChangeBatch, retrying only the two documented transient conditions."""
    for attempt in range(tries):
        try:
            resp = r53.change_resource_record_sets(
                HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
            )
            return resp["ChangeInfo"]["Id"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("PriorRequestNotComplete", "Throttling") or attempt == tries - 1:
                raise
            time.sleep(2.0 * (attempt + 1))


def _list_all(r53, zone_id, **extra):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    kwargs.update(extra)
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _at(rrsets, name, rtype):
    return [r for r in rrsets if r["Name"] == name and r["Type"] == rtype]


def _probe_zone_gone(r53, zone_id):
    try:
        r53.get_hosted_zone(Id=zone_id)
        return False
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "NoSuchHostedZone"


def _empty_and_delete_zone(r53, zone_id):
    def _non_apex():
        return [r for r in _list_all(r53, zone_id) if r["Type"] not in ("NS", "SOA")]

    leftovers = _non_apex()
    # Alias records first: an alias whose target is a record in the SAME zone blocks that
    # target's deletion.
    leftovers.sort(key=lambda r: 0 if r.get("AliasTarget") else 1)
    if leftovers:
        try:
            _change(
                r53, zone_id,
                [{"Action": "DELETE", "ResourceRecordSet": r} for r in leftovers],
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidChangeBatch":
                raise
            for rrs in leftovers:  # a set already gone must not strand the rest
                try:
                    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": rrs}])
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") != "InvalidChangeBatch" or (
                        "not found" not in str(exc)
                    ):
                        raise
    try:
        _poll(
            _non_apex, lambda rem: rem == [],
            timeout_s=45.0, interval_s=2.0,
            what=f"the non-apex record sets in {zone_id} to clear before DeleteHostedZone",
        )
    except AssertionError:
        print(f"[route53-cleanup] LEAK: hosted zone {zone_id} still holds record sets and "
              f"cannot be deleted; it bills $0.50/month until removed by hand")
        raise
    r53.delete_hosted_zone(Id=zone_id)
    _poll(
        lambda: _probe_zone_gone(r53, zone_id), lambda gone: gone,
        timeout_s=45.0, interval_s=2.0,
        what=f"GetHostedZone({zone_id}) to report NoSuchHostedZone after DeleteHostedZone",
    )


def _create_zone(ctx, r53, name=None):
    """Create one public hosted zone and register its emptying teardown.

    Public, not private: a private zone needs a VPC, and TestDNSAnswer only evaluates public zones.
    """
    zone_name = name or _zone_name(ctx)
    resp = r53.create_hosted_zone(
        Name=zone_name,
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "candidates_09 P0", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"]


def _wait_insync(r53, change_id, timeout_s=60.0):
    return _poll(
        lambda: r53.get_change(Id=change_id),
        lambda resp: resp["ChangeInfo"]["Status"] == "INSYNC",
        timeout_s=timeout_s, interval_s=2.0,
        what=f"change {change_id} to reach INSYNC",
    )


def _answer(r53, zone_id, record, rtype="A"):
    return r53.test_dns_answer(HostedZoneId=zone_id, RecordName=record, RecordType=rtype)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestDNSAnswer actually EVALUATES the routing policy: a weight of 0 is never answered
    while a nonzero sibling exists, and flipping the weights flips the answer.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy-weighted.html
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    record = f"wt.{zone_name}"

    def _weighted(set_id, weight, value):
        return {
            "Name": record, "Type": "A", "TTL": 60,
            "SetIdentifier": set_id, "Weight": weight,
            "ResourceRecords": [{"Value": value}],
        }

    change_id = _change(r53, zone_id, [
        {"Action": "CREATE", "ResourceRecordSet": _weighted("hot", 255, "203.0.113.71")},
        {"Action": "CREATE", "ResourceRecordSet": _weighted("cold", 0, "203.0.113.72")},
    ])
    # TestDNSAnswer queries a Route 53 name server, so unlike ListResourceRecordSets it does
    # need the change to have propagated. This is the one place an INSYNC wait is load-bearing.
    _wait_insync(r53, change_id)

    resp = _poll(
        lambda: _answer(r53, zone_id, record),
        lambda r: r.get("RecordData") == ["203.0.113.71"],
        timeout_s=40.0, interval_s=2.0,
        what=f"TestDNSAnswer({record}) to return only the weight-255 record 203.0.113.71",
    )
    # The whole answer envelope is contract, not just the data.
    assert resp["RecordData"] == ["203.0.113.71"], (
        f"a 0-weight sibling must never be answered while a nonzero sibling exists: {resp}"
    )
    assert resp["ResponseCode"] == "NOERROR", f"expected NOERROR: {resp}"
    assert resp["RecordType"] == "A", f"RecordType must be echoed: {resp}"
    assert resp["Protocol"] == "UDP", f"Protocol must default to UDP: {resp}"
    # The trailing dot is the one tolerated variation: the request carries the fully qualified
    # name and AWS may echo it without the root label.
    assert resp["RecordName"].rstrip(".") == record.rstrip("."), (
        f"RecordName must echo the queried name: {resp}"
    )
    assert resp["Nameserver"], f"Nameserver must name the server that answered: {resp}"

    # --- flip the weights; the answer must flip with them. ---
    _change(r53, zone_id, [
        {"Action": "UPSERT", "ResourceRecordSet": _weighted("hot", 0, "203.0.113.71")},
        {"Action": "UPSERT", "ResourceRecordSet": _weighted("cold", 255, "203.0.113.72")},
    ])
    flipped = _poll(
        lambda: _answer(r53, zone_id, record),
        lambda r: r.get("RecordData") == ["203.0.113.72"],
        timeout_s=60.0, interval_s=2.0,
        what=f"TestDNSAnswer({record}) to follow the reweighted group to 203.0.113.72",
    )
    assert flipped["RecordData"] == ["203.0.113.72"], (
        f"after the flip only the new weight-255 record may be answered: {flipped}"
    )
    assert flipped["ResponseCode"] == "NOERROR", flipped

    # --- and the stored state agrees with the evaluated answer: both siblings still exist,
    # with the weights swapped. An emulator must not have deleted the 0-weight record. ---
    group = _at(_list_all(r53, zone_id), record, "A")
    assert len(group) == 2, f"both siblings must survive the reweighting: {group}"
    assert {r["SetIdentifier"]: r["Weight"] for r in group} == {"hot": 0, "cold": 255}, group

    # --- a name that does not exist in the zone answers NXDOMAIN, proving the evaluation is
    # against the zone's contents rather than a fixed reply. ---
    missing = f"absent.{zone_name}"
    nx = _answer(r53, zone_id, missing)
    assert nx["ResponseCode"] == "NXDOMAIN", (
        f"an unknown name in the zone must answer NXDOMAIN: {nx}"
    )
    assert nx.get("RecordData") in ([], None), (
        f"NXDOMAIN must carry no record data: {nx}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
