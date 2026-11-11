"""rrset-wildcard-name-returned-octal-escaped."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-wildcard-name-returned-octal-escaped"
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
    """Route 53 normalises record-set names on the way in: a wildcard '*' comes back as the
    octal escape '\\052', mixed case comes back lower-cased, and the normalised form is the SAME
    record set -- creating it again under either spelling is a duplicate.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    wildcard_sent = f"*.{zone_name}"
    wildcard_escaped = f"\\052.{zone_name}"
    mixed_sent = f"MiXeD.{zone_name}"
    mixed_folded = f"mixed.{zone_name}"

    _change(r53, zone_id, [
        {"Action": "CREATE", "ResourceRecordSet": {
            "Name": wildcard_sent, "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.81"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {
            "Name": mixed_sent, "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.82"}]}},
    ])
    rrsets = _poll(
        lambda: _list_all(r53, zone_id),
        lambda got: len(got) == 4,  # the two new records plus the apex NS and SOA
        timeout_s=30.0, interval_s=2.0,
        what="both normalised record sets plus the apex NS+SOA to appear",
    )
    names = [r["Name"] for r in rrsets]

    # --- the wildcard is returned octal-escaped, never verbatim. ---
    assert wildcard_escaped in names, (
        f"the wildcard must be returned as {wildcard_escaped!r}, got {names}"
    )
    assert wildcard_sent not in names, (
        f"the wildcard must NOT be returned verbatim as {wildcard_sent!r}, got {names}"
    )
    star = _at(rrsets, wildcard_escaped, "A")
    assert len(star) == 1, f"exactly one wildcard record set: {rrsets}"
    assert star[0]["TTL"] == 60, star
    assert star[0]["ResourceRecords"] == [{"Value": "203.0.113.81"}], star

    # --- the mixed-case name is returned lower-cased, never verbatim. ---
    assert mixed_folded in names, (
        f"the name must be returned lower-cased as {mixed_folded!r}, got {names}"
    )
    assert mixed_sent not in names, (
        f"the name must NOT be returned verbatim as {mixed_sent!r}, got {names}"
    )
    folded = _at(rrsets, mixed_folded, "A")
    assert len(folded) == 1 and folded[0]["ResourceRecords"] == [{"Value": "203.0.113.82"}], (
        f"the lower-cased record must hold the values it was created with: {folded}"
    )

    # --- break exactly one thing: create the wildcard a second time, spelled the OTHER way.
    # Normalisation means both spellings name one record set, so this is a duplicate. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": wildcard_escaped, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": "203.0.113.83"}],
            },
        }]),
        f"CREATE of {wildcard_escaped}, the escaped spelling of the existing {wildcard_sent}",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    assert msg == (
        f"[Tried to create resource record set [name='{wildcard_escaped}', type='A'] "
        f"but it already exists]"
    ), f"the escaped spelling must collide with the verbatim one: {msg!r}"
    # the effect is absent: still one wildcard, still the original value
    star_after = _at(_list_all(r53, zone_id), wildcard_escaped, "A")
    assert len(star_after) == 1, f"the refused CREATE must not add a second wildcard: {star_after}"
    assert star_after[0]["ResourceRecords"] == [{"Value": "203.0.113.81"}], (
        f"the refused CREATE must not overwrite the wildcard: {star_after}"
    )

    # --- the same collision the other way round: create the mixed-case name in the case it
    # was folded to. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": mixed_folded, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": "203.0.113.84"}],
            },
        }]),
        f"CREATE of {mixed_folded}, the folded spelling of the existing {mixed_sent}",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    assert msg == (
        f"[Tried to create resource record set [name='{mixed_folded}', type='A'] "
        f"but it already exists]"
    ), f"the folded spelling must collide with the mixed-case one: {msg!r}"

    # --- the control case: the normalised form round-trips through the WRITE path too. The
    # record set as returned -- escaped name and all -- is accepted verbatim as a DELETE. ---
    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": star[0]}])
    _poll(
        lambda: _at(_list_all(r53, zone_id), wildcard_escaped, "A"),
        lambda got: got == [],
        timeout_s=30.0, interval_s=2.0,
        what=f"{wildcard_escaped} to disappear after a DELETE using the escaped name",
    )

    # --- restore: with the wildcard's own record gone, the CREATE refused above (the escaped
    # spelling) is no longer a duplicate. The identical call, unchanged, must now succeed -- this
    # is the half of the refusal that proves the block was the conflict, not a blanket rejection
    # of the escaped spelling. ---
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": wildcard_escaped, "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.85"}],
        },
    }])
    restored = _poll(
        lambda: _at(_list_all(r53, zone_id), wildcard_escaped, "A"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the identical CREATE of {wildcard_escaped} to succeed now that the conflict is gone",
    )
    assert restored[0]["ResourceRecords"] == [{"Value": "203.0.113.85"}], (
        f"the restored CREATE must take effect: {restored}"
    )

    # and the other record is untouched by any of this
    survivor = _at(_list_all(r53, zone_id), mixed_folded, "A")
    assert len(survivor) == 1, f"the unrelated record must survive: {survivor}"
    assert survivor[0]["ResourceRecords"] == [{"Value": "203.0.113.82"}], survivor

    # --- the same restore for the mixed-case collision: delete the folded record, then the
    # identical CREATE refused above must now succeed too. ---
    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": folded[0]}])
    _poll(
        lambda: _at(_list_all(r53, zone_id), mixed_folded, "A"),
        lambda got: got == [],
        timeout_s=30.0, interval_s=2.0,
        what=f"{mixed_folded} to disappear after a DELETE using the folded name",
    )
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": mixed_folded, "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.86"}],
        },
    }])
    restored_mixed = _poll(
        lambda: _at(_list_all(r53, zone_id), mixed_folded, "A"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the identical CREATE of {mixed_folded} to succeed now that the conflict is gone",
    )
    assert restored_mixed[0]["ResourceRecords"] == [{"Value": "203.0.113.86"}], (
        f"the restored CREATE must take effect: {restored_mixed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
