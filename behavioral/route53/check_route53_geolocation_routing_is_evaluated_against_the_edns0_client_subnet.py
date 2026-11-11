"""route53-geolocation-routing-is-evaluated-against-the-edns0-client-subnet."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route53-geolocation-routing-is-evaluated-against-the-edns0-client-subnet"
GROUP = 'resource-record-sets'
SERVICES = ['route53']

# Geolocation is evaluated against the query's source address, which a check cannot choose, so
# TestDNSAnswer's EDNS0ClientSubnetIP is the only way to vary the apparent client location.


# ---- generic helpers --------------------------------------------------------------------------


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code") or ""


def _msg_of(exc):
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    """Poll an observable condition to a bounded deadline."""
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


# ---- hosted zones -----------------------------------------------------------------------------
# Teardown raises rather than swallowing (a zone that cannot be emptied keeps billing), deletes
# alias sets before their in-zone targets, and waits on API state rather than INSYNC. Zone names
# use the RFC 2606 reserved `.test` TLD.

def _caller_reference():
    return f"cr-{secrets.token_hex(16)}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    return f"{raw}.example.test."


def _change(r53, zone_id, changes, tries=4):
    """Submit a ChangeBatch, retrying only the two documented transient conditions."""
    for attempt in range(tries):
        try:
            return r53.change_resource_record_sets(
                HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
            )["ChangeInfo"]["Id"]
        except ClientError as exc:
            if _code_of(exc) not in ("PriorRequestNotComplete", "Throttling") \
                    or attempt == tries - 1:
                raise
            time.sleep(2.0 * (attempt + 1))


def _list_all(r53, zone_id, **extra):
    """Every record set in the zone, fully paginated."""
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
    want = name.rstrip(".").lower()
    return [r for r in rrsets if r["Name"].rstrip(".").lower() == want and r["Type"] == rtype]


def _zone_gone(r53, zone_id):
    try:
        r53.get_hosted_zone(Id=zone_id)
        return False
    except ClientError as exc:
        return _code_of(exc) == "NoSuchHostedZone"


def _empty_and_delete_zone(r53, zone_id):
    def _non_apex():
        return [r for r in _list_all(r53, zone_id) if r["Type"] not in ("NS", "SOA")]

    leftovers = _non_apex()
    # Alias records first: an alias whose target is a record in the SAME zone blocks that
    # target's deletion.
    leftovers.sort(key=lambda r: 0 if r.get("AliasTarget") else 1)
    if leftovers:
        try:
            _change(r53, zone_id,
                    [{"Action": "DELETE", "ResourceRecordSet": r} for r in leftovers])
        except ClientError:
            for rrs in leftovers:  # one unbatchable set must not strand the rest
                try:
                    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": rrs}])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "HostedZoneNotFound",
                        "NoSuchHealthCheck",
                        "NoSuchHostedZone",
                    ):
                        raise
    try:
        _poll(_non_apex, lambda rem: rem == [], timeout_s=60.0, interval_s=2.0,
              what=f"the non-apex record sets in {zone_id} to clear before DeleteHostedZone")
    except AssertionError:
        print(f"[route53-cleanup] LEAK: hosted zone {zone_id} still holds record sets and "
              f"cannot be deleted; it bills $0.50/month until removed by hand")
        raise
    r53.delete_hosted_zone(Id=zone_id)
    _poll(lambda: _zone_gone(r53, zone_id), lambda gone: gone,
          timeout_s=60.0, interval_s=2.0,
          what=f"GetHostedZone({zone_id}) to report NoSuchHostedZone after DeleteHostedZone")


def _create_zone(ctx, r53, prefix="zone"):
    """Create a public hosted zone with its teardown registered at creation time.

    Returns (zone id, zone name, delegated nameservers); a zone deleted within 12 hours is not billed.
    """
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx, prefix),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "sim2real-behav ga-depth", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return zone_id, resp["HostedZone"]["Name"], resp["DelegationSet"]["NameServers"]


def _wait_insync(r53, change_id, timeout_s=180.0):
    """Poll GetChange to INSYNC and return the status observed."""
    return _poll(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda st: st == "INSYNC",
        timeout_s=timeout_s, interval_s=2.0,
        what=f"change {change_id} to reach INSYNC",
    )

# Client subnets from long-standing national allocations; a reassigned range fails loudly.
#   DE  Deutsche Telekom AG, 62.155.0.0/16      (RIPE NCC, DE)
#   JP  NTT Communications, 210.130.0.0/16      (APNIC, JP)
#   US  Google Public DNS anycast, 8.8.8.0/24   (ARIN, US) -- matched by NEITHER sibling, so it
#       must fall through to the CountryCode='*' default and become NXDOMAIN once that is deleted.
# RFC 5737 TEST-NET ranges cannot be used here: they have no country at all, so they would not
# exercise the fall-through for the documented reason.
_DE_SUBNET, _JP_SUBNET, _US_SUBNET = "62.155.0.0", "210.130.0.0", "8.8.8.0"
_DE, _JP, _DEFAULT = "203.0.113.80", "203.0.113.81", "203.0.113.82"


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Geolocation records resolve per client subnet: DE and JP subnets get their records and any
    other subnet gets the '*' default. With the default deleted, the unmatched subnet gets NODATA
    (NOERROR, no records), not NXDOMAIN or an arbitrary sibling: the name still exists.

    Reference: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-policy-geo.html
    """
    r53 = ctx.client("route53")
    zone_id, zone_name, _ns_list = _create_zone(ctx, r53)
    name = f"geo.{zone_name}"

    def _geo(set_id, country, value):
        return {"Name": name, "Type": "A", "TTL": 60, "SetIdentifier": set_id,
                "GeoLocation": {"CountryCode": country}, "ResourceRecords": [{"Value": value}]}

    default_rrs = _geo("default", "*", _DEFAULT)
    _wait_insync(r53, _change(r53, zone_id, [
        {"Action": "UPSERT", "ResourceRecordSet": _geo("de", "DE", _DE)},
        {"Action": "UPSERT", "ResourceRecordSet": _geo("jp", "JP", _JP)},
        {"Action": "UPSERT", "ResourceRecordSet": default_rrs},
    ]))

    def _ask(subnet):
        return r53.test_dns_answer(
            HostedZoneId=zone_id, RecordName=name, RecordType="A",
            EDNS0ClientSubnetIP=subnet, EDNS0ClientSubnetMask="24")

    # Poll ONE of the three to the propagated state and then read all three: the geo group either
    # has propagated or it has not, and polling each separately would let a stale sibling answer.
    _poll(lambda: _ask(_DE_SUBNET), lambda r: r.get("RecordData") == [_DE],
          timeout_s=240, interval_s=5,
          what=f"TestDNSAnswer({name}) from a German client subnet to return the DE record")
    de, jp, other = _ask(_DE_SUBNET), _ask(_JP_SUBNET), _ask(_US_SUBNET)

    assert de["RecordData"] == [_DE], (
        f"a German client subnet ({_DE_SUBNET}/24) must get the CountryCode='DE' record: {de!r}"
    )
    assert jp["RecordData"] == [_JP], (
        f"a Japanese client subnet ({_JP_SUBNET}/24) must get the CountryCode='JP' record: {jp!r}"
    )
    assert other["RecordData"] == [_DEFAULT], (
        f"a client subnet in neither country ({_US_SUBNET}/24) must fall through to the "
        f"CountryCode='*' default, not to an arbitrary sibling: {other!r}"
    )
    assert de["ResponseCode"] == "NOERROR" and jp["ResponseCode"] == "NOERROR", (de, jp)

    # --- break exactly one thing: delete the '*' default. The fall-through must disappear. ---
    _wait_insync(r53, _change(
        r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": default_rrs}]))
    other_after = _poll(
        lambda: _ask(_US_SUBNET), lambda r: r.get("RecordData") == [],
        timeout_s=240, interval_s=5,
        what=f"TestDNSAnswer({name}) from an unmatched client subnet to stop returning any record "
             f"once the CountryCode='*' default is deleted")
    de_after = _ask(_DE_SUBNET)

    assert other_after["RecordData"] == [], (
        f"with the default deleted, a client subnet matching NO geolocation sibling must be "
        f"answered with no record at all -- never with an arbitrary sibling: {other_after!r}"
    )
    assert other_after["ResponseCode"] == "NOERROR", (
        f"the unmatched answer must be NODATA (NOERROR with no records) and not NXDOMAIN: the "
        f"name still exists, because the DE and JP siblings are still there. Measured against "
        f"real AWS 2026-09-10: {other_after!r}"
    )
    assert de_after["RecordData"] == [_DE], (
        f"positive control: deleting the default must not disturb the matched countries: "
        f"{de_after!r}"
    )
    group_after = _at(_list_all(r53, zone_id), name, "A")
    assert {r["SetIdentifier"] for r in group_after} == {"de", "jp"}, (
        f"only the '*' default may have been removed: {group_after!r}"
    )
    assert {r["GeoLocation"]["CountryCode"] for r in group_after} == {"DE", "JP"}, group_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
