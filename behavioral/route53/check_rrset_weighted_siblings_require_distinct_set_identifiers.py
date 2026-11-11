"""rrset-weighted-siblings-require-distinct-set-identifiers."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-weighted-siblings-require-distinct-set-identifiers"
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


def _expect_error(fn, what):
    """Require fn to raise ClientError; return (Error.Code, Error.Message). Never swallows success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Weighted routing is the one case where several record sets legally share a name and type,
    and SetIdentifier is what keeps them apart: distinct identifiers coexist, a duplicate
    identifier is refused, and a simple (unidentified) record cannot join the group.
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

    # --- the positive: two weighted siblings at the SAME name and type. ---
    _change(r53, zone_id, [
        {"Action": "CREATE", "ResourceRecordSet": _weighted("blue", 200, "203.0.113.41")},
        {"Action": "CREATE", "ResourceRecordSet": _weighted("green", 55, "203.0.113.42")},
    ])
    group = _poll(
        lambda: _at(_list_all(r53, zone_id), record, "A"),
        lambda got: len(got) == 2,
        timeout_s=30.0, interval_s=2.0,
        what=f"both weighted siblings at {record} to appear in ListResourceRecordSets",
    )
    by_id = {r["SetIdentifier"]: r for r in group}
    assert set(by_id) == {"blue", "green"}, (
        f"both SetIdentifiers must round-trip: {group}"
    )
    assert by_id["blue"]["Weight"] == 200, f"Weight must round-trip exactly: {by_id['blue']}"
    assert by_id["green"]["Weight"] == 55, f"Weight must round-trip exactly: {by_id['green']}"
    assert by_id["blue"]["ResourceRecords"] == [{"Value": "203.0.113.41"}], by_id["blue"]
    assert by_id["green"]["ResourceRecords"] == [{"Value": "203.0.113.42"}], by_id["green"]
    assert by_id["blue"]["TTL"] == 60 and by_id["green"]["TTL"] == 60, group

    # --- break exactly one thing: reuse an existing SetIdentifier. Because identity is the
    # triple, this is a duplicate CREATE of the "blue" record set, not a third sibling. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [
            {"Action": "CREATE", "ResourceRecordSet": _weighted("blue", 1, "203.0.113.43")},
        ]),
        f"CREATE of a third weighted record at {record} reusing SetIdentifier 'blue'",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    # A reused SetIdentifier is a duplicate CREATE; the echo carries the full identity triple,
    # including set-identifier='blue', showing Route 53 keys record sets on (Name, Type, SetIdentifier).
    assert msg == (
        f"[Tried to create resource record set [name='{record}', type='A', "
        f"set-identifier='blue'] but it already exists]"
    ), f"expected the duplicate-CREATE discriminator naming the triple, got {msg!r}"

    # the effect is absent: still exactly two siblings, and "blue" is untouched
    after = _at(_list_all(r53, zone_id), record, "A")
    assert len(after) == 2, f"the refused CREATE must not add a third sibling: {after}"
    blue_after = {r["SetIdentifier"]: r for r in after}["blue"]
    assert blue_after["Weight"] == 200, (
        f"the refused CREATE must not overwrite 'blue': {blue_after}"
    )
    assert blue_after["ResourceRecords"] == [{"Value": "203.0.113.41"}], blue_after

    # --- break a different single thing: a SIMPLE record (no SetIdentifier, no Weight) at the
    # same name and type. Simple and weighted routing cannot coexist at one name+type. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": record, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": "203.0.113.44"}],
            },
        }]),
        f"CREATE of a simple record at {record}, which already holds a weighted group",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    # Route 53 does NOT use the bracketed [name='...', type='...']
    # echo here -- that form belongs to the duplicate-CREATE fault above. A simple record
    # colliding with an existing routed group gets its own prose, and notably it does NOT mention
    # SetIdentifier at all:
    #   "RRSet with DNS name <n>, type A cannot be created as other RRSets exist with the same
    #    name and type."
    # Asserting it verbatim is what separates this refusal from the duplicate-CREATE one; an
    # emulator that returns the "already exists" wording here has collapsed two distinct rules.
    assert msg == (
        f"[RRSet with DNS name {record}, type A cannot be created as other RRSets exist with "
        f"the same name and type.]"
    ), f"expected the simple-vs-routed-group wording, got {msg!r}"
    still = _at(_list_all(r53, zone_id), record, "A")
    assert len(still) == 2, f"the refused simple record must not join the group: {still}"
    assert all("SetIdentifier" in r for r in still), (
        f"every surviving sibling must still be weighted: {still}"
    )

    # --- the control case: a THIRD distinct SetIdentifier is still accepted, so the refusals
    # were about identity collisions and not a cap on the group. ---
    _change(r53, zone_id, [
        {"Action": "CREATE", "ResourceRecordSet": _weighted("red", 0, "203.0.113.45")},
    ])
    final = _poll(
        lambda: _at(_list_all(r53, zone_id), record, "A"),
        lambda got: len(got) == 3,
        timeout_s=30.0, interval_s=2.0,
        what=f"the control sibling 'red' at {record} to land",
    )
    assert {r["SetIdentifier"] for r in final} == {"blue", "green", "red"}, final
    # Weight 0 is legal and must round-trip as 0, not be dropped as falsy.
    assert {r["SetIdentifier"]: r["Weight"] for r in final}["red"] == 0, final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
