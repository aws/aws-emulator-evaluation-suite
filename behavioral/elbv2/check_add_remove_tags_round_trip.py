"""add-remove-tags-round-trip."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-remove-tags-round-trip"
GROUP = "control-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTags/DescribeTags/RemoveTags round-trip tags on a target group precisely, then
    DeleteTargetGroup proves the arn is gone and unusable for further tag operations."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, net["vpc_id"])
    arn = tg["TargetGroupArn"]

    elbv2.add_tags(ResourceArns=[arn], Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "qa"}])

    described = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]
    tag_map = {t["Key"]: t["Value"] for t in described["Tags"]}
    assert tag_map.get("env") == "sim2real", tag_map
    assert tag_map.get("owner") == "qa", tag_map

    elbv2.remove_tags(ResourceArns=[arn], TagKeys=["owner"])
    described2 = elbv2.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]
    tag_map2 = {t["Key"]: t["Value"] for t in described2["Tags"]}
    assert "owner" not in tag_map2, tag_map2
    assert tag_map2.get("env") == "sim2real", tag_map2

    elbv2.delete_target_group(TargetGroupArn=arn)
    try:
        elbv2.describe_target_groups(TargetGroupArns=[arn])
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "TargetGroupNotFound", exc.response["Error"]
        assert exc.response["Error"].get("Message") == "One or more target groups not found", exc.response["Error"]
    else:
        raise AssertionError(f"describe_target_groups succeeded on deleted target group {arn}")

    try:
        elbv2.add_tags(ResourceArns=[arn], Tags=[{"Key": "post-delete", "Value": "x"}])
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "TargetGroupNotFound", exc.response["Error"]
        assert exc.response["Error"].get("Message") == f"Target groups '{arn}' not found", exc.response["Error"]
    else:
        raise AssertionError(f"add_tags succeeded on deleted target group {arn}")


_GONE = {"TargetGroupNotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn):
    """Teardown: done once the resource is gone; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "") not in _GONE:
            raise


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s)
        if len(by_az) >= 2:
            chosen = list(by_az.values())[:2]
            return {"vpc_id": vpc_id, "subnet_ids": [s["SubnetId"] for s in chosen]}

    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: ec2.delete_subnet(SubnetId=sid)))
        ec2.create_tags(Resources=[sid], Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip"}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_target_group_when_free(elbv2, arn)))
    return tg



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=2.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
