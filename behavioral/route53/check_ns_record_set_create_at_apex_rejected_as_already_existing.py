"""ns-record-set-create-at-apex-rejected-as-already-existing."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "ns-record-set-create-at-apex-rejected-as-already-existing"
GROUP = "resource-record-sets"
SERVICES = ["route53"]


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx):
    raw = ctx.unique_name("sim2real-behav-zone").lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _list_all_record_sets(r53, zone_id):
    out = []
    kwargs = {"HostedZoneId": zone_id}
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _empty_and_delete_zone(r53, zone_id, apex_name):
    for rrs in _list_all_record_sets(r53, zone_id):
        if rrs["Name"] == apex_name and rrs["Type"] in ("NS", "SOA"):
            continue
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
        )
    r53.delete_hosted_zone(Id=zone_id)


def _expect_error(fn, what):
    """Require fn to raise ClientError; return (code, message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an NS record set at the zone apex is rejected because one already exists;
    the identical create at a non-apex name succeeds, so the refusal is specific to the apex.
    """
    r53 = ctx.client("route53")
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "behavioral-check", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    zone_name = resp["HostedZone"]["Name"]
    name_servers = resp["DelegationSet"]["NameServers"]
    ctx.on_cleanup(lambda z=zone_id, n=zone_name: _empty_and_delete_zone(r53, z, n))

    apex_before = [
        r for r in _list_all_record_sets(r53, zone_id)
        if r["Name"] == zone_name and r["Type"] == "NS"
    ]
    assert len(apex_before) == 1, f"expected exactly one apex NS record set, got {apex_before}"

    # --- break exactly one thing: create an NS record set at the apex. ---
    code, msg = _expect_error(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [{
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": zone_name,
                        "Type": "NS",
                        "TTL": 172800,
                        "ResourceRecords": [{"Value": n} for n in name_servers],
                    },
                }]
            },
        ),
        f"CREATE of an NS record set at the apex of {zone_name}",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch creating apex NS, got {code}: {msg}"
    expected_message = (
        f"[Tried to create resource record set [name='{zone_name}', type='NS'] but it already exists]"
    )
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    apex_after = [
        r for r in _list_all_record_sets(r53, zone_id)
        if r["Name"] == zone_name and r["Type"] == "NS"
    ]
    assert apex_after == apex_before, (
        f"the rejected create must leave the apex NS record set unchanged, got {apex_after}"
    )

    # --- control: the identical create at a non-apex name succeeds. ---
    child_name = f"child.{zone_name}"
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [{
                "Action": "CREATE",
                "ResourceRecordSet": {
                    "Name": child_name,
                    "Type": "NS",
                    "TTL": 172800,
                    "ResourceRecords": [{"Value": n} for n in name_servers],
                },
            }]
        },
    )
    created = [
        r for r in _list_all_record_sets(r53, zone_id)
        if r["Name"] == child_name and r["Type"] == "NS"
    ]
    assert len(created) == 1, f"expected the control NS record set at {child_name} to appear, got {created}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
