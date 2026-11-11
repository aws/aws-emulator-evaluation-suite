"""rrset-strict-match-delete-requires-exact-values."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rrset-strict-match-delete-requires-exact-values"
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
    """Require fn to raise ClientError; return (code, joined message). Never swallows success.

    InvalidChangeBatch models a `messages` LIST alongside Error.Message and both carry the
    discriminating text, so the fragment is looked for across both.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        parts = [err.get("Message") or ""] + list(exc.response.get("messages") or [])
        return err.get("Code"), " | ".join(p for p in parts if p)
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
    """A DELETE change must match the existing record set EXACTLY (name, type, TTL, values) or
    be refused with the record left untouched.
    """
    r53 = ctx.client("route53")
    zone_id, zone_name = _create_zone(ctx, r53)
    record = f"www.{zone_name}"

    _change(r53, zone_id, [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": record, "Type": "A", "TTL": 300,
            "ResourceRecords": [{"Value": "203.0.113.10"}],
        },
    }])
    # The API is read-after-write consistent for record-set metadata (ChangeInfo PENDING refers
    # to DNS propagation, not API visibility), but poll briefly so a slow write is not a flake.
    _poll(
        lambda: _at(_list_all(r53, zone_id), record, "A"),
        lambda got: len(got) == 1,
        timeout_s=30.0, interval_s=2.0,
        what=f"{record} A to appear in ListResourceRecordSets",
    )

    def _current():
        got = _at(_list_all(r53, zone_id), record, "A")
        assert len(got) == 1, f"expected exactly one {record} A record set, got {got}"
        return got[0]

    created = _current()
    assert created["TTL"] == 300, f"TTL not echoed: {created}"
    assert created["ResourceRecords"] == [{"Value": "203.0.113.10"}], created

    # --- break exactly one thing: the value. Name, type and TTL are all correct. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "DELETE",
            "ResourceRecordSet": {
                "Name": record, "Type": "A", "TTL": 300,
                "ResourceRecords": [{"Value": "203.0.113.99"}],
            },
        }]),
        f"DELETE of {record} A with a non-matching value 203.0.113.99",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    # InvalidChangeBatch is a catch-all; the [name='...', type='...'] echo of the offending
    # record set is what distinguishes this fault from the other batch validations.
    mismatch = (
        f"[Tried to delete resource record set [name='{record}', type='A'] but the values "
        "provided do not match the current values]"
    )
    assert msg == mismatch, f"expected message {mismatch!r}, got {msg!r}"
    # the effect is absent: the record survives, byte for byte
    unchanged = _current()
    assert unchanged["ResourceRecords"] == [{"Value": "203.0.113.10"}], (
        f"a refused DELETE must not alter the record: {unchanged}"
    )
    assert unchanged["TTL"] == 300, unchanged

    # --- break exactly one thing: the TTL. Name, type and values are all correct. ---
    code, msg = _expect_error(
        lambda: _change(r53, zone_id, [{
            "Action": "DELETE",
            "ResourceRecordSet": {
                "Name": record, "Type": "A", "TTL": 60,
                "ResourceRecords": [{"Value": "203.0.113.10"}],
            },
        }]),
        f"DELETE of {record} A with a non-matching TTL 60",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    assert msg == mismatch, f"expected message {mismatch!r}, got {msg!r}"
    still_there = _current()
    assert still_there["TTL"] == 300, f"a refused DELETE must not alter the TTL: {still_there}"
    assert still_there["ResourceRecords"] == [{"Value": "203.0.113.10"}], still_there

    # --- the control case: an exact-match DELETE is accepted and the record is gone. ---
    change_id = _change(r53, zone_id, [{
        "Action": "DELETE", "ResourceRecordSet": created,
    }])
    assert change_id, "DELETE with an exact match must return a ChangeInfo id"
    _poll(
        lambda: _at(_list_all(r53, zone_id), record, "A"),
        lambda got: got == [],
        timeout_s=30.0, interval_s=2.0,
        what=f"{record} A to disappear after an exact-match DELETE",
    )
    # the zone's own apex records are untouched by all of the above. This is a membership assertion,
    # not an ordering one, so sorting the observed types is sound here.
    after = _list_all(r53, zone_id)
    assert sorted(r["Type"] for r in after) == ["NS", "SOA"], (
        f"zone should hold only its apex NS+SOA after the record is deleted: {after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
