"""rrset-change-batch-all-or-nothing-on-partial-failure."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-change-batch-all-or-nothing-on-partial-failure"
GROUP = 'resource-record-sets'
SERVICES = ['route53']


# Zone teardown raises rather than swallowing errors: DeleteHostedZone fails with
# HostedZoneNotEmpty while any non-NS/SOA record set remains, and a leaked zone keeps billing.
# It waits on ListResourceRecordSets rather than INSYNC, because HostedZoneNotEmpty is
# evaluated against API state. `.test` is an RFC 2606 reserved TLD; AWS reserves
# example.com/.org/.net for public zones.

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
    """Create ONE public hosted zone and register its emptying teardown at creation time.

    Public, not private: a private zone needs a VPC, and TestDNSAnswer only evaluates public
    zones.
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
    """A ChangeBatch is atomic on failure: when its second change is a duplicate CREATE, the
    whole batch is rejected and the valid first change is not applied. Partial application
    would leave the caller with an error and no idea how much of its intent landed."""
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    existing = f"existing.{zone_name}"
    fresh = f"fresh.{zone_name}"

    # --- setup: one record that already exists, so a later CREATE of it is invalid. ---
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": existing, "Type": "A", "TTL": 300,
            "ResourceRecords": [{"Value": "203.0.113.10"}],
        },
    }])
    _poll(
        lambda: _at(_list_all(r53, zone_id), existing, "A"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"{existing} A to appear in ListResourceRecordSets",
    )

    # --- one batch: change[0] is perfectly valid, change[1] duplicates an existing set. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [
            {"Action": "CREATE", "ResourceRecordSet": {
                "Name": fresh, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": "203.0.113.30"}]}},
            {"Action": "CREATE", "ResourceRecordSet": {
                "Name": existing, "Type": "A", "TTL": 300,
                "ResourceRecords": [{"Value": "203.0.113.10"}]}},
        ]),
        f"a batch whose second change duplicates the existing {existing} A",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    # the message must blame the SECOND change, not the first -- an emulator that reports the
    # wrong offender is telling the caller to fix the wrong line.
    expected_message = (
        f"[Tried to create resource record set [name='{existing}', type='A'] but it already exists]"
    )
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    # --- the whole point: change[0] must NOT have been applied. ---
    rrsets = _list_all(r53, zone_id)
    assert _at(rrsets, fresh, "A") == [], (
        f"a rejected batch must apply NONE of its changes, but {fresh} exists: {rrsets}"
    )
    # and the pre-existing record is untouched
    survivor = _at(rrsets, existing, "A")
    assert len(survivor) == 1, f"{existing} must still exist exactly once: {rrsets}"
    assert survivor[0]["TTL"] == 300, survivor
    assert survivor[0]["ResourceRecords"] == [{"Value": "203.0.113.10"}], survivor

    # --- the control case: the same valid change on its own is accepted, proving the batch
    # was rejected for its invalid member and not because change[0] was itself bad. ---
    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": fresh, "Type": "A", "TTL": 60,
            "ResourceRecords": [{"Value": "203.0.113.30"}],
        },
    }])
    got = _poll(
        lambda: _at(_list_all(r53, zone_id), fresh, "A"),
        lambda found: len(found) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"the control CREATE of {fresh} to land",
    )
    assert got[0]["TTL"] == 60, got
    assert got[0]["ResourceRecords"] == [{"Value": "203.0.113.30"}], got


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
