"""overly-permissive-associate-vpc-with-public-zone."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-associate-vpc-with-public-zone"
GROUP = 'vpc-association'
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


def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING an association real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(
        f"real AWS rejects AssociateVPCWithHostedZone on a public zone, but it SUCCEEDED and "
        f"returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[overly-permissive] AssociateVPCWithHostedZone on a PUBLIC zone must fail: VPCs only apply to private zones."""
    r53 = ctx.client("route53")

    # Positive control: the same call, same account, succeeds on a PRIVATE zone -- so the
    # rejection below is specific to the zone being public, not a stand-in for "every
    # AssociateVPCWithHostedZone call fails" (e.g. from a permissions problem in this account).
    control_vpc = _create_vpc(ctx)
    control_zone = _create_zone(ctx, r53, private=True, vpc_id=control_vpc)
    control_zone_id = control_zone["HostedZone"]["Id"]
    extra_vpc = _create_vpc(ctx)
    r53.associate_vpc_with_hosted_zone(
        HostedZoneId=control_zone_id, VPC={"VPCId": extra_vpc, "VPCRegion": ctx.region}
    )
    control_vpcs = {v["VPCId"] for v in r53.get_hosted_zone(Id=control_zone_id).get("VPCs", [])}
    assert extra_vpc in control_vpcs, (
        f"positive control failed: associating a VPC with a PRIVATE zone must succeed; "
        f"got zone VPCs {control_vpcs}"
    )

    zone = _create_zone(ctx, r53, private=False)
    zone_id = zone["HostedZone"]["Id"]
    rejected_vpc = _create_vpc(ctx)

    code, message = _error_code(
        lambda: r53.associate_vpc_with_hosted_zone(
            HostedZoneId=zone_id, VPC={"VPCId": rejected_vpc, "VPCRegion": ctx.region}
        )
    )
    assert code == "PublicZoneVPCAssociation", (
        f"expected PublicZoneVPCAssociation, got {code!r}"
    )
    expected = f"Attempting to associate public zone: {zone_id.rsplit('/', 1)[-1]} with vpc: {rejected_vpc}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read at the destination shows the rejected VPC never
    # attached to the public zone.
    zone_vpcs = {v["VPCId"] for v in r53.get_hosted_zone(Id=zone_id).get("VPCs", [])}
    assert rejected_vpc not in zone_vpcs, f"rejected VPC leaked into public zone VPCs: {zone_vpcs}"
    assert not zone_vpcs, f"a public zone must never report any associated VPCs: {zone_vpcs}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
