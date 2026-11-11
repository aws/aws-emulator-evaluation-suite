"""rrset-cname-at-zone-apex-rejected."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-cname-at-zone-apex-rejected"
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
    """A CNAME is legal at a subdomain but must be refused at the zone apex, because the apex
    already carries the zone's mandatory NS and SOA and RFC 1034 forbids a CNAME coexisting
    with other data at the same name.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    sub = f"www.{zone_name}"

    # --- control first: the identical CNAME one label down is perfectly legal. ---
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": sub, "Type": "CNAME", "TTL": 300,
            "ResourceRecords": [{"Value": "target.example.test."}],
        },
    }])
    _poll(
        lambda: _at(_list_all(r53, zone_id), sub, "CNAME"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"{sub} CNAME to appear in ListResourceRecordSets",
    )
    control = _at(_list_all(r53, zone_id), sub, "CNAME")[0]
    assert control["ResourceRecords"] == [{"Value": "target.example.test."}], control
    assert control["TTL"] == 300, control

    # --- break exactly one thing: move the same record to the apex. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "CREATE",
            "ResourceRecordSet": {
                "Name": zone_name, "Type": "CNAME", "TTL": 300,
                "ResourceRecords": [{"Value": "target.example.test."}],
            },
        }]),
        f"CREATE of a CNAME at the zone apex {zone_name}",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    # InvalidChangeBatch is a catch-all; the message is the only thing distinguishing an apex
    # CNAME from the dozens of other batch validations, so pin it, not just the code.
    expected_message = (
        f"[RRSet of type CNAME with DNS name {zone_name} is not permitted at apex in zone "
        f"{zone_name}]"
    )
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    # --- the effect is absent: the apex still holds exactly its NS and SOA, no CNAME. ---
    rrsets = _list_all(r53, zone_id)
    apex = [r for r in rrsets if r["Name"] == zone_name]
    assert sorted(r["Type"] for r in apex) == ["NS", "SOA"], (
        f"apex must hold exactly NS+SOA after the refused CNAME: {apex}"
    )
    assert _at(rrsets, zone_name, "CNAME") == [], f"apex CNAME must not exist: {rrsets}"

    # --- and the control is still intact: the refusal was scoped to the one bad change. ---
    still = _at(_list_all(r53, zone_id), sub, "CNAME")
    assert len(still) == 1, f"the legal subdomain CNAME must survive: {still}"
    assert still[0]["ResourceRecords"] == [{"Value": "target.example.test."}], still


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
