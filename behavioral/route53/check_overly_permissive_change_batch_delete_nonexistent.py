"""overly-permissive-change-batch-delete-nonexistent."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-change-batch-delete-nonexistent"
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


def _create_vpc(ctx):
    # Route 53 validates VPC existence, so a real VPC is required (fake ids are rejected).
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda v=vpc_id: ec2.delete_vpc(VpcId=v))
    # private hosted zone association requires DNS support/hostnames on the VPC
    try:
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    except Exception:
        pass
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc")}],
    )
    return vpc_id


def _create_zone(ctx, r53, *, private=False, vpc_id=None, vpc_region=None,
                 name=None, comment=None):
    kwargs = {
        "Name": name or _zone_name(ctx),
        "CallerReference": _caller_reference(),
        "HostedZoneConfig": {"Comment": comment or "behavioral-check", "PrivateZone": private},
    }
    if private:
        kwargs["VPC"] = {
            "VPCRegion": vpc_region or ctx.region,
            "VPCId": vpc_id or _create_vpc(ctx),
        }
    resp = r53.create_hosted_zone(**kwargs)
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    return resp


def _expect_error(fn, what):
    """Require fn to raise ClientError; return (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] DELETE of a record set that doesn't exist must fail with InvalidChangeBatch, not no-op."""
    r53 = ctx.client("route53")
    zone = _create_zone(ctx, r53)
    zone_id = zone["HostedZone"]["Id"]
    zone_name = zone["HostedZone"]["Name"]
    control_name = f"control.{zone_name}"
    ghost_name = f"ghost.{zone_name}"

    # Positive control: ChangeResourceRecordSets can succeed at all in this zone. Without this,
    # "rejects DELETE of a record that doesn't exist" is indistinguishable from "rejects every
    # ChangeResourceRecordSets call".
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [{
                "Action": "CREATE",
                "ResourceRecordSet": {
                    "Name": control_name, "Type": "A", "TTL": 60,
                    "ResourceRecords": [{"Value": "192.0.2.10"}],
                },
            }]
        },
    )
    created = _list_all_record_sets(r53, zone_id)
    assert any(r["Name"] == control_name for r in created), (
        f"positive control CREATE of {control_name} did not take effect: {created}"
    )

    code, msg = _expect_error(
        lambda: r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": ghost_name,
                            "Type": "A",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": "192.0.2.100"}],
                        },
                    }
                ]
            },
        ),
        f"DELETE of {ghost_name} A, which was never created",
    )
    assert code == "InvalidChangeBatch", f"expected InvalidChangeBatch, got {code}: {msg}"
    expected = f"[Tried to delete resource record set [name='{ghost_name}', type='A'] but it was not found]"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Effect absent, via an independent read: the refused DELETE must not have created the
    # ghost it was refusing to delete, and must not have disturbed the unrelated control record.
    after = _list_all_record_sets(r53, zone_id)
    assert not any(r["Name"] == ghost_name for r in after), (
        f"a refused DELETE must not bring the target it was refusing to delete into existence: {after}"
    )
    assert any(r["Name"] == control_name for r in after), (
        f"a refused DELETE must not disturb unrelated record sets: {after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
