"""overly-permissive-hosted-zone-caller-reference-replay."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-hosted-zone-caller-reference-replay"
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
    """[overly-permissive] CreateHostedZone is NOT idempotent: replaying an identical request
    (same CallerReference AND same name) must fail with HostedZoneAlreadyExists rather than
    silently returning the existing zone or creating a duplicate."""
    r53 = ctx.client("route53")
    name = _zone_name(ctx)
    ref = _caller_reference()
    first = r53.create_hosted_zone(
        Name=name, CallerReference=ref, HostedZoneConfig={"Comment": "idem", "PrivateZone": False}
    )
    zone_id = first["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))

    err = _client_error(
        lambda: r53.create_hosted_zone(
            Name=name, CallerReference=ref, HostedZoneConfig={"Comment": "idem", "PrivateZone": False}
        )
    )
    assert err["Code"] == "HostedZoneAlreadyExists", err
    assert err["Message"] == "A hosted zone has already been created with the specified caller reference.", err

    # the original zone must survive the rejected replay, and remain the only one with that name
    got = r53.get_hosted_zone(Id=zone_id)
    assert got["HostedZone"]["Name"] == name, got["HostedZone"]["Name"]
    listed = r53.list_hosted_zones_by_name(DNSName=name, MaxItems="10")
    same = [z for z in listed["HostedZones"] if z["Name"] == name]
    assert len(same) == 1, same


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
