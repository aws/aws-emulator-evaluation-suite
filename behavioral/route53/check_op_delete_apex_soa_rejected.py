"""op-delete-apex-soa-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "op-delete-apex-soa-rejected"
GROUP = 'resource-record-sets'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
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


def _empty_and_delete_zone(r53, zone_id):
    # A hosted zone bills $0.50/month, charged at creation and NOT prorated, and
    # DeleteHostedZone fails with HostedZoneNotEmpty while any non-NS/SOA record set
    # remains -- so swallowing every exception here would silently leak a billed zone.
    for rrs in _list_all_record_sets(r53, zone_id):
        if rrs["Type"] in ("NS", "SOA"):
            continue
        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
        )
    r53.delete_hosted_zone(Id=zone_id)


def _create_zone(ctx, r53, *, name=None, comment=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": False},
    }
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


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
    """Deleting the apex SOA record is rejected with InvalidChangeBatch and the record survives.

    An ordinary record-set delete on the same zone succeeds, so the refusal is specific to the SOA.
    """
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-op-soa"))
    zone_id = resp["HostedZone"]["Id"]
    zone_name = resp["HostedZone"]["Name"]

    rrsets = _list_all_record_sets(r53, zone_id)
    soa = next((r for r in rrsets if r["Type"] == "SOA"), None)
    assert soa is not None, f"expected a default SOA record in a new zone, got {rrsets}"

    # --- control first: an ordinary, non-apex record can be created and deleted. ---
    sub_name = f"ctrl.{zone_name}"
    sub_record = {
        "Name": sub_name, "Type": "TXT", "TTL": 300,
        "ResourceRecords": [{"Value": '"control"'}],
    }
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": sub_record}]},
    )
    created = [r for r in _list_all_record_sets(r53, zone_id) if r["Name"] == sub_name]
    assert len(created) == 1, f"expected the control TXT record to appear, got {created}"

    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": created[0]}]},
    )
    remaining = [r for r in _list_all_record_sets(r53, zone_id) if r["Name"] == sub_name]
    assert remaining == [], f"expected the control TXT record to be deletable, got {remaining}"

    # --- break exactly one thing: delete the apex SOA record. ---
    code, msg = _expect_error(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": soa}]},
        ),
        f"DELETE of the apex SOA record in {zone_name}",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch deleting apex SOA, got {code}: {msg}"
    expected_message = "[A HostedZone must contain exactly one SOA record.]"
    assert msg == expected_message, f"expected message {expected_message!r}, got {msg!r}"

    after = _list_all_record_sets(r53, zone_id)
    assert any(r["Type"] == "SOA" for r in after), "apex SOA record must survive a rejected delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
