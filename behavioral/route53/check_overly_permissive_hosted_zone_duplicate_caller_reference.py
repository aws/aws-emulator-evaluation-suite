"""overly-permissive-hosted-zone-duplicate-caller-reference."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-hosted-zone-duplicate-caller-reference"
GROUP = 'hosted-zone'
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


def _client_error(fn):
    """The ``Error`` of the ClientError ``fn`` raises. A call that succeeds fails the check: a
    target accepting what AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] Reusing a CallerReference with a DIFFERENT zone name must fail, not silently succeed."""
    r53 = ctx.client("route53")
    ref = _caller_reference()
    zone_b_name = _zone_name(ctx, "zone-b")
    first = r53.create_hosted_zone(
        Name=_zone_name(ctx, "zone-a"), CallerReference=ref, HostedZoneConfig={"Comment": "a", "PrivateZone": False}
    )
    ctx.on_cleanup(lambda z=first["HostedZone"]["Id"]: _empty_and_delete_zone(r53, z))

    err = _client_error(
        lambda: r53.create_hosted_zone(
            Name=zone_b_name, CallerReference=ref, HostedZoneConfig={"Comment": "b", "PrivateZone": False}
        )
    )
    assert err["Code"] == "HostedZoneAlreadyExists", err
    assert err["Message"] == "A hosted zone has already been created with the specified caller reference.", err

    # the rejected call must leave no trace: zone-b must not exist under any id
    listed = r53.list_hosted_zones_by_name(DNSName=zone_b_name, MaxItems="10")
    same = [z for z in listed["HostedZones"] if z["Name"] == zone_b_name]
    assert same == [], same

    # restore: the SAME name with a FRESH caller reference must succeed — proving the rejection
    # above was specifically about caller-reference reuse, not about zone-b's name being invalid.
    second = r53.create_hosted_zone(
        Name=zone_b_name,
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "b", "PrivateZone": False},
    )
    ctx.on_cleanup(lambda z=second["HostedZone"]["Id"]: _empty_and_delete_zone(r53, z))

    listed_after = r53.list_hosted_zones_by_name(DNSName=zone_b_name, MaxItems="10")
    same_after = [z for z in listed_after["HostedZones"] if z["Name"] == zone_b_name]
    assert len(same_after) == 1, same_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
