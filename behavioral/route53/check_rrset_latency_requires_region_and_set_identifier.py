"""rrset-latency-requires-region-and-set-identifier."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-latency-requires-region-and-set-identifier"
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


_MANAGED_TAGS = [{"Key": "sim2real", "Value": "rrset-latency-requires-region-and-set-identifier"},
                 {"Key": "sim2real:managed", "Value": "true"},
                 {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


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
    # CreateHostedZone has no Tags param; tag immediately after so a tag search can
    # find this zone even if this process dies before the cleanup above runs.
    r53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id.split("/")[-1], AddTags=_MANAGED_TAGS
    )
    return zone_id, resp["HostedZone"]["Name"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A latency-based record set needs BOTH a Region and a SetIdentifier, and the Region must
    be a real AWS region: a legal pair coexists at one name, a missing SetIdentifier is refused,
    and an unknown region string is refused.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    record = f"lat.{zone_name}"

    def _latency(set_id, region, value):
        return {
            "Name": record, "Type": "A", "TTL": 60,
            "SetIdentifier": set_id, "Region": region,
            "ResourceRecords": [{"Value": value}],
        }

    # --- the positive: two latency siblings, distinct regions and identifiers. ---
    # us-east-1/eu-west-1 are the record's Region values under test, not the region this check
    # runs in; any two distinct real regions would do.
    _change(r53, zone_id, [
        {"Action": "CREATE",
         "ResourceRecordSet": _latency("east", "us-east-1", "203.0.113.51")},
        {"Action": "CREATE",
         "ResourceRecordSet": _latency("west", "eu-west-1", "203.0.113.52")},
    ])
    group = _poll(
        lambda: _at(_list_all(r53, zone_id), record, "A"),
        lambda got: len(got) == 2,
        timeout_s=30.0, interval_s=2.0,
        what=f"both latency siblings at {record} to appear in ListResourceRecordSets",
    )
    by_id = {r["SetIdentifier"]: r for r in group}
    assert set(by_id) == {"east", "west"}, f"both SetIdentifiers must round-trip: {group}"
    assert by_id["east"]["Region"] == "us-east-1", (
        f"Region must round-trip exactly: {by_id['east']}"
    )
    assert by_id["west"]["Region"] == "eu-west-1", (
        f"Region must round-trip exactly: {by_id['west']}"
    )
    assert by_id["east"]["ResourceRecords"] == [{"Value": "203.0.113.51"}], by_id["east"]
    assert by_id["west"]["ResourceRecords"] == [{"Value": "203.0.113.52"}], by_id["west"]
    # a latency record must NOT acquire a Weight it was never given
    assert "Weight" not in by_id["east"], (
        f"a latency record must not echo a Weight: {by_id['east']}"
    )

    # --- break exactly one thing: drop the SetIdentifier from an otherwise valid record. ---
    lonely = f"lonely.{zone_name}"
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": lonely, "Type": "A", "TTL": 60, "Region": "us-east-1",
                "ResourceRecords": [{"Value": "203.0.113.53"}],
            },
        }]),
        f"CREATE of a latency record {lonely} with a Region but no SetIdentifier",
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code}: {msg}"
    # Route 53 answers "Invalid request: Missing field 'SetIdentifier' in Change with [...]", a
    # request-shape fault naming the field, so the quoted field name is asserted.
    assert msg == (
        f"Invalid request: Missing field 'SetIdentifier' in Change with "
        f"[Action=CREATE, Name={lonely}, Type=A, SetIdentifier=null]"
    ), f"the message must name SetIdentifier as the missing field: {msg!r}"
    assert _at(_list_all(r53, zone_id), lonely, "A") == [], (
        f"the refused record {lonely} must not exist"
    )

    # --- break a different single thing: an unknown region on an otherwise valid record. ---
    bogus = f"bogus-region.{zone_name}"
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": bogus, "Type": "A", "TTL": 60,
                "SetIdentifier": "nowhere", "Region": "xx-fake-1",
                "ResourceRecords": [{"Value": "203.0.113.54"}],
            },
        }]),
        f"CREATE of a latency record {bogus} whose Region is not an AWS region",
    )
    # Region is a modelled enum that botocore does not validate client-side, so the server must
    # refuse it. Unlike the missing SetIdentifier, request shape passes and the change batch then
    # fails against the region catalogue: InvalidChangeBatch, not InvalidInput.
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    assert msg == "[Cannot find region 'xx-fake-1'. No changes made.]", (
        f"the refusal must name the region it could not resolve: {msg!r}"
    )
    assert _at(_list_all(r53, zone_id), bogus, "A") == [], (
        f"the refused record {bogus} must not exist"
    )

    # --- the control case: the original latency group is untouched by both refusals. ---
    final = _at(_list_all(r53, zone_id), record, "A")
    assert len(final) == 2, f"the latency group must be unchanged: {final}"
    assert {r["SetIdentifier"]: r["Region"] for r in final} == {
        "east": "us-east-1", "west": "eu-west-1",
    }, final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
