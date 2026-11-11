"""op-rrset-name-outside-zone-rejected."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "op-rrset-name-outside-zone-rejected"
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
    try:
        for rrs in _list_all_record_sets(r53, zone_id):
            if rrs["Type"] in ("NS", "SOA"):
                continue
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
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise


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


def _client_error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the change to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A record set whose name is not within the hosted zone's domain must be rejected with
    InvalidChangeBatch. An in-zone create on the same wiring is the positive control proving the
    target can create records here at all, so the rejection is specific to the out-of-zone name."""
    r53 = ctx.client("route53")
    resp = _create_zone(ctx, r53, name=_zone_name(ctx, "chk-op-outside"))
    zone_id = resp["HostedZone"]["Id"]
    zone_name = resp["HostedZone"]["Name"]
    in_zone_name = ctx.unique_name("chk-inzone-") + "." + zone_name
    foreign_name = ctx.unique_name("chk-foreign-") + ".not-my-zone-at-all.com."

    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": in_zone_name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.100"}],
                    },
                }
            ]
        },
    )
    names = {r["Name"] for r in _list_all_record_sets(r53, zone_id)}
    assert in_zone_name in names, f"positive control: in-zone create must succeed and be visible, got {names}"

    code, message = _client_error(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": foreign_name,
                            "Type": "A",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": "192.0.2.150"}],
                        },
                    }
                ]
            },
        )
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch for out-of-zone name, got {code}"
    expected_message = f"[RRSet with DNS name {foreign_name} is not permitted in zone {zone_name}]"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    names = {r["Name"] for r in _list_all_record_sets(r53, zone_id)}
    assert foreign_name not in names, f"rejected change must not create the out-of-zone record, found in {names}"
    assert names == {zone_name, in_zone_name}, (
        f"zone must contain only the apex records and the control record, got {names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
