"""rrset-listing-is-reverse-label-sorted."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-listing-is-reverse-label-sorted"
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
    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=zone_id.rsplit("/", 1)[-1],
        AddTags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    return zone_id, resp["HostedZone"]["Name"]


def _reverse_label_key(rrs):
    """Route 53's documented ListResourceRecordSets order: by DNS name with the labels compared
    in REVERSE (top-level domain first), then by record type."""
    labels = tuple(reversed(rrs["Name"].rstrip(".").split(".")))
    return (labels, rrs["Type"])


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRecordSets returns record sets in Route 53's documented order -- DNS name
    with the labels compared in REVERSE, then type -- and MaxItems paging walks that same
    sequence via NextRecordName/NextRecordType without gaps, repeats or reordering.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)

    # Submitted in a deliberately anti-sorted order so that echoing the insertion order fails.
    # The pair b.a / a.b is the discriminator: reverse-label order puts b.a FIRST (its 4th
    # label 'a' precedes 'b'), while a plain lexicographic name sort puts a.b first.
    planned = [
        {"Name": f"zzz.{zone_name}", "Type": "AAAA", "TTL": 60,
         "ResourceRecords": [{"Value": "2001:db8::1"}]},
        {"Name": f"a.b.{zone_name}", "Type": "A", "TTL": 60,
         "ResourceRecords": [{"Value": "203.0.113.61"}]},
        {"Name": f"zzz.{zone_name}", "Type": "A", "TTL": 60,
         "ResourceRecords": [{"Value": "203.0.113.62"}]},
        {"Name": f"b.a.{zone_name}", "Type": "A", "TTL": 60,
         "ResourceRecords": [{"Value": "203.0.113.63"}]},
    ]
    _change(r53, zone_id, [{"Action": "CREATE", "ResourceRecordSet": r} for r in planned])
    _poll(
        lambda: _list_all(r53, zone_id),
        lambda rrsets: len(rrsets) == len(planned) + 2,  # + the zone's own apex NS and SOA
        timeout_s=30.0, interval_s=2.0,
        what=f"all {len(planned)} record sets plus the apex NS+SOA to appear",
    )

    observed = _list_all(r53, zone_id)
    observed_seq = [(r["Name"], r["Type"]) for r in observed]

    # every planned record set is present exactly once, before any claim about their order
    for want in planned:
        found = _at(observed, want["Name"], want["Type"])
        assert len(found) == 1, (
            f"expected exactly one {want['Name']} {want['Type']}, got {found}"
        )
        assert found[0]["ResourceRecords"] == want["ResourceRecords"], found

    # Only the expectation is sorted; the observed sequence is compared exactly as returned.
    expected_seq = [
        (r["Name"], r["Type"]) for r in sorted(observed, key=_reverse_label_key)
    ]
    assert observed_seq == expected_seq, (
        "ListResourceRecordSets must return reverse-label-then-type order.\n"
        f"  returned: {observed_seq}\n  expected: {expected_seq}"
    )

    # Pin the discriminating pair explicitly, so a failure says which rule was broken rather
    # than just dumping two lists.
    idx = {nt: i for i, nt in enumerate(observed_seq)}
    b_a = (f"b.a.{zone_name}", "A")
    a_b = (f"a.b.{zone_name}", "A")
    assert idx[b_a] < idx[a_b], (
        f"reverse-label order puts {b_a[0]} before {a_b[0]}; a plain lexicographic name sort "
        f"is what puts them the other way round. returned: {observed_seq}"
    )
    # A plain name sort would have produced a different sequence -- assert that, so this check
    # can never silently degrade into one that both orders satisfy.
    naive_seq = [
        (r["Name"], r["Type"]) for r in sorted(observed, key=lambda x: (x["Name"], x["Type"]))
    ]
    assert naive_seq != expected_seq, (
        "the fixture stopped discriminating reverse-label order from lexicographic order"
    )
    # The apex NS and SOA sort first, NS before SOA -- asserted positionally, not as a set.
    assert observed_seq[0] == (zone_name, "NS"), f"apex NS must be first: {observed_seq}"
    assert observed_seq[1] == (zone_name, "SOA"), f"apex SOA must be second: {observed_seq}"
    # At one name, A precedes AAAA.
    assert idx[(f"zzz.{zone_name}", "A")] < idx[(f"zzz.{zone_name}", "AAAA")], observed_seq

    # --- MaxItems paging walks the identical sequence. MaxItems is a STRING on this API. ---
    paged = []
    kwargs = {"HostedZoneId": zone_id, "MaxItems": "1"}
    pages = 0
    while True:
        pages += 1
        assert pages <= len(observed_seq) + 1, (
            f"paging did not terminate within {len(observed_seq)} pages: {paged}"
        )
        resp = r53.list_resource_record_sets(**kwargs)
        page = resp["ResourceRecordSets"]
        assert len(page) == 1, f"MaxItems=1 must return exactly one record set, got {page}"
        # MaxItems and IsTruncated are both required output members.
        assert resp["MaxItems"] == "1", (
            f"MaxItems must be echoed as the string it was sent as: {resp.get('MaxItems')!r}"
        )
        paged.append((page[0]["Name"], page[0]["Type"]))
        if not resp.get("IsTruncated"):
            assert "NextRecordName" not in resp, (
                f"the final page must not carry NextRecordName: {resp}"
            )
            break
        assert resp["IsTruncated"] is True, f"IsTruncated must be a real boolean: {resp}"
        # NextRecordName/Type must point at the NEXT record in the sequence, not the current one.
        nxt = (resp["NextRecordName"], resp["NextRecordType"])
        assert nxt == observed_seq[len(paged)], (
            f"page {pages} NextRecord* must address record {len(paged)} "
            f"({observed_seq[len(paged)]}), got {nxt}"
        )
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]

    assert paged == observed_seq, (
        "paging must walk the same sequence as an unpaged list.\n"
        f"  paged:   {paged}\n  unpaged: {observed_seq}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
