"""rrset-cname-conflicts-with-same-name-record."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-cname-conflicts-with-same-name-record"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CNAME cannot coexist with any other record type at the same DNS name, and the rule is
    symmetric: an A blocks a later CNAME and a CNAME blocks a later A; removing the blocker
    lets the identical refused CREATE succeed (RFC 1034: a CNAME must be alone at its name).
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    a_first = f"a-first.{zone_name}"
    cname_first = f"cname-first.{zone_name}"

    # --- setup: one name owned by an A, one name owned by a CNAME. Both legal. ---
    _change(r53, zone_id, [
        {"Action": "CREATE", "ResourceRecordSet": {
            "Name": a_first, "Type": "A", "TTL": 300,
            "ResourceRecords": [{"Value": "203.0.113.10"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {
            "Name": cname_first, "Type": "CNAME", "TTL": 300,
            "ResourceRecords": [{"Value": "target.example.test."}]}},
    ])
    _poll(
        lambda: _list_all(r53, zone_id),
        lambda rrsets: len(_at(rrsets, a_first, "A")) == 1
        and len(_at(rrsets, cname_first, "CNAME")) == 1,
        timeout_s=30.0, interval_s=2.0,
        what="both setup record sets to appear in ListResourceRecordSets",
    )

    # --- direction 1: break exactly one thing -- add a CNAME where an A already lives. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": a_first, "Type": "CNAME", "TTL": 300,
                "ResourceRecords": [{"Value": "target.example.test."}],
            },
        }]),
        f"CREATE of a CNAME at {a_first}, which already holds an A",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    # The code is a catch-all; the message is the discriminator. The two directions use
    # different sentences: CNAME-over-A does not name the blocking type, A-over-CNAME names the
    # CNAME as the blocker, so both are asserted verbatim.
    assert msg == (
        f"[RRSet of type CNAME with DNS name {a_first} is not permitted as it conflicts with "
        f"other records with the same DNS name in zone {zone_name}]"
    ), f"expected the CNAME-over-existing-record wording, got {msg!r}"
    # the effect is absent: that name still holds exactly the one A record set
    at_a = [r for r in _list_all(r53, zone_id) if r["Name"] == a_first]
    assert len(at_a) == 1 and at_a[0]["Type"] == "A", (
        f"{a_first} must still hold only its A record set: {at_a}"
    )
    assert at_a[0]["ResourceRecords"] == [{"Value": "203.0.113.10"}], at_a

    # --- restore: the conflict is a state, not an invalid input -- remove the A and the
    # IDENTICAL CREATE that was just refused must now succeed. ---
    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": at_a[0]}])
    _poll(
        lambda: _at(_list_all(r53, zone_id), a_first, "A"),
        lambda got: got == [],
        timeout_s=30.0, interval_s=2.0,
        what=f"the A record at {a_first} to clear before retrying the identical CNAME create",
    )
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": a_first, "Type": "CNAME", "TTL": 300,
            "ResourceRecords": [{"Value": "target.example.test."}],
        },
    }])
    now_at_a = _poll(
        lambda: _at(_list_all(r53, zone_id), a_first, "CNAME"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the identical CNAME create at {a_first} to succeed once the A is gone",
    )
    assert now_at_a[0]["ResourceRecords"] == [{"Value": "target.example.test."}], now_at_a

    # --- direction 2: the mirror image -- add an A where a CNAME already lives. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": cname_first, "Type": "A", "TTL": 300,
                "ResourceRecords": [{"Value": "203.0.113.20"}],
            },
        }]),
        f"CREATE of an A at {cname_first}, which already holds a CNAME",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    assert msg == (
        f"[RRSet of type A with DNS name {cname_first} is not permitted because a conflicting "
        f"RRSet of type CNAME with the same DNS name already exists in zone {zone_name}]"
    ), f"expected the blocked-by-an-existing-CNAME wording, got {msg!r}"
    at_cname = [r for r in _list_all(r53, zone_id) if r["Name"] == cname_first]
    assert len(at_cname) == 1 and at_cname[0]["Type"] == "CNAME", (
        f"{cname_first} must still hold only its CNAME record set: {at_cname}"
    )
    assert at_cname[0]["ResourceRecords"] == [{"Value": "target.example.test."}], at_cname

    # --- restore: same treatment, mirrored -- remove the CNAME and the IDENTICAL A create
    # that was just refused must now succeed. ---
    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": at_cname[0]}])
    _poll(
        lambda: _at(_list_all(r53, zone_id), cname_first, "CNAME"),
        lambda got: got == [],
        timeout_s=30.0, interval_s=2.0,
        what=f"the CNAME record at {cname_first} to clear before retrying the identical A create",
    )
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": cname_first, "Type": "A", "TTL": 300,
            "ResourceRecords": [{"Value": "203.0.113.20"}],
        },
    }])
    now_at_cname = _poll(
        lambda: _at(_list_all(r53, zone_id), cname_first, "A"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the identical A create at {cname_first} to succeed once the CNAME is gone",
    )
    assert now_at_cname[0]["ResourceRecords"] == [{"Value": "203.0.113.20"}], now_at_cname

    # --- the control case: a CNAME at a name that owns nothing is still accepted, so the
    # refusals above were about the conflict and not a blanket CNAME ban. ---
    fresh = f"fresh.{zone_name}"
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": fresh, "Type": "CNAME", "TTL": 300,
            "ResourceRecords": [{"Value": "target.example.test."}],
        },
    }])
    _poll(
        lambda: _at(_list_all(r53, zone_id), fresh, "CNAME"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the control CNAME {fresh} to appear in ListResourceRecordSets",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
