"""rrset-atomic-batch-delete-and-create."""

from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "rrset-atomic-batch-delete-and-create"
GROUP = 'resource-record-sets'
SERVICES = ['route53']


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    # example.com/.org/.net are reserved by AWS for public zones; use a non-reserved suffix.
    return f"{raw}.sim2real-probe-zone.com."


def _poll_status(probe, done, timeout_s=60.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for condition; last response={last}"
            )
        time.sleep(interval_s)


def _wait_insync(r53, change_id, timeout_s=90, interval_s=2.0):
    return _poll_status(
        lambda: r53.get_change(Id=change_id),
        lambda resp: resp["ChangeInfo"]["Status"] == "INSYNC",
        timeout_s=timeout_s, interval_s=interval_s,
    )


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
    def _non_apex():
        return [r for r in _list_all_record_sets(r53, zone_id) if r["Type"] not in ("NS", "SOA")]

    for rrs in _non_apex():
        try:
            r53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrs}]},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "HostedZoneNotFound",
                "NoSuchHealthCheck",
                "NoSuchHostedZone",
            ):
                raise

    try:
        _poll_status(_non_apex, lambda rem: rem == [], timeout_s=45.0, interval_s=2.0)
    except AssertionError:
        # A hosted zone bills $0.50/month, charged at creation and NOT prorated, and
        # DeleteHostedZone fails with HostedZoneNotEmpty while any non-NS/SOA record set
        # remains -- swallowing this would silently leak a zone that bills forever.
        print(f"[route53-cleanup] LEAK: hosted zone {zone_id} still holds record sets and "
              f"cannot be deleted; it bills $0.50/month until removed by hand")
        raise

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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A single ChangeBatch that DELETEs and CREATEs the same name/type is applied atomically."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-op-atomic"))
    zone_id = resp["HostedZone"]["Id"]
    record_name = "atomic." + resp["HostedZone"]["Name"]

    create = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.40"}],
                    },
                }
            ]
        },
    )
    _wait_insync(r53, create["ChangeInfo"]["Id"])

    # Replace via DELETE(old) + CREATE(new) for the SAME name/type in one
    # ChangeBatch -- the AWS-documented pattern for changing a record's value
    # without a window in which no record exists for that name/type. What is
    # asserted below is that this pairing is honored as a coherent replace:
    # exactly one record survives, holding the new value.
    swap = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.40"}],
                    },
                },
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.41"}],
                    },
                },
            ]
        },
    )
    _wait_insync(r53, swap["ChangeInfo"]["Id"])

    rrsets = _list_all_record_sets(r53, zone_id)
    match = [r for r in rrsets if r["Name"] == record_name and r["Type"] == "A"]
    assert len(match) == 1, (
        f"expected exactly one {record_name} A record set after the atomic swap, got {match}"
    )
    values = [rr["Value"] for rr in match[0]["ResourceRecords"]]
    assert values == ["192.0.2.41"], (
        f"expected the atomic DELETE+CREATE batch to leave {record_name} A at 192.0.2.41, got {values}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
