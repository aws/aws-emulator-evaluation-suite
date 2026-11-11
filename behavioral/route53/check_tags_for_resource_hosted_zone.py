"""tags-for-resource-hosted-zone."""

from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "tags-for-resource-hosted-zone"
GROUP = 'tags'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangeTagsForResource add/remove on a hosted zone round-trips through ListTagsForResource."""
    r53 = ctx.client("route53")
    zone = _create_zone(ctx, r53)
    zone_id = zone["HostedZone"]["Id"]
    # ResourceId for tagging APIs is the bare zone id without the "/hostedzone/" prefix
    bare_id = zone_id.split("/")[-1]

    r53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=bare_id, AddTags=[{"Key": "team", "Value": "dns"}]
    )
    tags = r53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=bare_id)
    kv = {t["Key"]: t["Value"] for t in tags["ResourceTagSet"]["Tags"]}
    assert kv.get("team") == "dns", kv

    r53.change_tags_for_resource(ResourceType="hostedzone", ResourceId=bare_id, RemoveTagKeys=["team"])
    tags2 = r53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=bare_id)
    kv2 = {t["Key"]: t["Value"] for t in tags2["ResourceTagSet"]["Tags"]}
    assert "team" not in kv2, kv2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
