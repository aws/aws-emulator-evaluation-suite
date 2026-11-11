"""rrset-alias-excludes-ttl-and-resource-records."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-alias-excludes-ttl-and-resource-records"
GROUP = 'resource-record-sets'
SERVICES = ['route53']

# Route 53 reports all three value-shape violations below as one InvalidInput "exactly one of
# [AliasTarget, TTL+ResourceRecords, TrafficPolicyInstanceId]" message; its trailing "more than
# one" or "none" tells an alias that also carries TTL/ResourceRecords from a record with neither.
def _exactly_one_message(found, name):
    return (
        "Invalid request: Expected exactly one of [AliasTarget, all of [TTL, and ResourceRecords], "
        f"or TrafficPolicyInstanceId], but found {found} in Change with "
        f"[Action=CREATE, Name={name}, Type=A, SetIdentifier=null]"
    )


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
    """Require fn to raise ClientError; return (code, Error.Message). Never swallows success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An alias record set carries AliasTarget instead of TTL/ResourceRecords: it is listed with
    neither, and an alias supplying either one, or a record with values but no TTL, is refused.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    # AliasTarget.HostedZoneId takes the BARE zone id; GetHostedZone/CreateHostedZone return it
    # as "/hostedzone/Z...". An emulator that accepts the prefixed form here is over-permissive.
    bare_zone_id = zone_id.split("/")[-1]
    target = f"target.{zone_name}"
    alias = f"app.{zone_name}"

    # --- setup: a normal A record inside the zone, to be the alias target. ---
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": target, "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.20"}],
        },
    }])
    _poll(
        lambda: _at(_list_all(r53, zone_id), target, "A"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the alias target {target} to appear in ListResourceRecordSets",
    )

    # --- the positive: a same-zone alias, created with no TTL and no ResourceRecords. ---
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": alias, "Type": "A",
            "AliasTarget": {
                "HostedZoneId": bare_zone_id,
                "DNSName": target,
                "EvaluateTargetHealth": False,
            },
        },
    }])
    got = _poll(
        lambda: _at(_list_all(r53, zone_id), alias, "A"),
        lambda found: len(found) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the alias record {alias} to appear in ListResourceRecordSets",
    )
    rrs = got[0]
    assert "AliasTarget" in rrs, f"alias record must echo AliasTarget: {rrs}"
    assert "TTL" not in rrs, f"an alias record set must carry NO TTL, got {rrs}"
    assert "ResourceRecords" not in rrs, (
        f"an alias record set must carry NO ResourceRecords, got {rrs}"
    )
    at = rrs["AliasTarget"]
    assert at["DNSName"] == target, f"AliasTarget.DNSName must round-trip exactly: {at}"
    assert at["HostedZoneId"] == bare_zone_id, (
        f"AliasTarget.HostedZoneId must round-trip as the bare id {bare_zone_id}: {at}"
    )
    assert at["EvaluateTargetHealth"] is False, (
        f"EvaluateTargetHealth must round-trip as a real boolean False, got {at!r}"
    )

    # --- break exactly one thing: add a TTL to an otherwise identical alias. ---
    bad_ttl = f"bad-ttl.{zone_name}"
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": bad_ttl, "Type": "A", "TTL": 60,
                "AliasTarget": {
                    "HostedZoneId": bare_zone_id,
                    "DNSName": target,
                    "EvaluateTargetHealth": False,
                },
            },
        }]),
        f"CREATE of an alias record {bad_ttl} that also specifies a TTL",
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code}: {msg}"
    expected_message = _exactly_one_message("more than one", bad_ttl)
    assert msg == expected_message, (
        f"an alias that also carries a TTL must be reported as supplying MORE THAN ONE of the "
        f"three alternatives: expected {expected_message!r}, got {msg!r}"
    )
    assert _at(_list_all(r53, zone_id), bad_ttl, "A") == [], (
        f"the refused alias {bad_ttl} must not exist"
    )

    # --- break the other half of the same exclusion: ResourceRecords alongside an AliasTarget. ---
    bad_rr = f"bad-rr.{zone_name}"
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": bad_rr, "Type": "A",
                "ResourceRecords": [{"Value": "203.0.113.99"}],
                "AliasTarget": {
                    "HostedZoneId": bare_zone_id,
                    "DNSName": target,
                    "EvaluateTargetHealth": False,
                },
            },
        }]),
        f"CREATE of an alias record {bad_rr} that also specifies ResourceRecords",
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code}: {msg}"
    expected_message = _exactly_one_message("more than one", bad_rr)
    assert msg == expected_message, (
        f"an alias that also carries ResourceRecords must be refused by the same exactly-one "
        f"rule as the TTL case: expected {expected_message!r}, got {msg!r}"
    )
    assert _at(_list_all(r53, zone_id), bad_rr, "A") == [], (
        f"the refused alias {bad_rr} must not exist"
    )

    # --- break exactly one other thing: a non-alias record with values but no TTL. ---
    no_ttl = f"no-ttl.{zone_name}"
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": no_ttl, "Type": "A",
                "ResourceRecords": [{"Value": "203.0.113.21"}],
            },
        }]),
        f"CREATE of a non-alias record {no_ttl} with ResourceRecords but no TTL",
    )
    # Not an InvalidChangeBatch "MissingTTL" fault: the same InvalidInput exactly-one rule as the
    # alias cases above, reported as "found none".
    assert code == "InvalidInput", f"expected InvalidInput, got {code}: {msg}"
    expected_message = _exactly_one_message("none", no_ttl)
    assert msg == expected_message, (
        f"ResourceRecords without a TTL must be reported as supplying NONE of the three "
        f"alternatives -- TTL and ResourceRecords count as one alternative only together: "
        f"expected {expected_message!r}, got {msg!r}"
    )
    assert _at(_list_all(r53, zone_id), no_ttl, "A") == [], (
        f"the refused record {no_ttl} must not exist"
    )

    # --- the control case: both original record sets survive, unchanged. ---
    rrsets = _list_all(r53, zone_id)
    alias_after = _at(rrsets, alias, "A")
    assert len(alias_after) == 1, f"the valid alias must survive: {rrsets}"
    assert "TTL" not in alias_after[0], alias_after
    assert alias_after[0]["AliasTarget"]["DNSName"] == target, alias_after
    target_after = _at(rrsets, target, "A")
    assert len(target_after) == 1 and target_after[0]["TTL"] == 60, target_after
    assert target_after[0]["ResourceRecords"] == [{"Value": "203.0.113.20"}], target_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
