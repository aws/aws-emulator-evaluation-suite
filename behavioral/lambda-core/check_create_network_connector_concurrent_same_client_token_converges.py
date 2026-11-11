"""create-network-connector-concurrent-same-client-token-converges."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-connector-concurrent-same-client-token-converges"
GROUP = "concurrency"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racing CreateNetworkConnector calls sharing one ClientToken all converge to a single connector."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    token = ctx.unique_name("sim2real-token-")
    infra = _setup_operator_role_and_vpc(ctx, name)
    config = _vpc_egress_config([infra["subnet_id"]], [infra["sg_id"]])
    racers = 6

    def _create():
        return _create_connector_with_retry(lc, name, config, infra["role_arn"], token)

    with ThreadPoolExecutor(max_workers=racers) as pool:
        responses = list(pool.map(lambda _: _create(), range(racers)))

    ids = {r["Id"] for r in responses}
    arns = {r["Arn"] for r in responses}
    assert len(ids) == 1, f"racing creates with the same ClientToken produced {len(ids)} distinct connectors: {ids}"
    assert len(arns) == 1, f"racing creates with the same ClientToken produced {len(arns)} distinct ARNs: {arns}"

    connector_id = ids.pop()
    window = infra["teardown_window"]
    ctx.on_cleanup(lambda: _best_effort_delete(window, lc.delete_network_connector, Identifier=connector_id))

    listing = lc.list_network_connectors(MaxItems=100)
    matching = [c for c in listing["NetworkConnectors"] if c["Name"] == name]
    assert len(matching) == 1, f"expected exactly one persisted connector for the racing token, found {len(matching)}"


def _vpc_egress_config(subnet_ids, sg_ids=None, protocol="IPv4"):
    cfg = {
        "VpcEgressConfiguration": {
            "SubnetIds": subnet_ids,
            "NetworkProtocol": protocol,
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }
    if sg_ids:
        cfg["VpcEgressConfiguration"]["SecurityGroupIds"] = sg_ids
    return cfg


def _create_connector_with_retry(lc, name, config, role_arn, token, timeout_s=60, interval_s=5):
    """CreateNetworkConnector can reject with the OperatorRole not yet usable: IAM's own attached-policy
    read (already polled in _setup_operator_role_and_vpc) is a different, faster-converging consistency
    domain than the role becoming assumable by lambda-core itself. Retry the create call — the only
    observable signal for that second domain — instead of guessing how long it takes.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lc.create_network_connector(
                Name=name,
                Configuration=config,
                ClientToken=token,
                OperatorRole=role_arn,
                Tags={"sim2real": "true"},
            )
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


_NOT_FOUND = {"ResourceNotFoundException", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
              "InvalidGroup.NotFound"}
_IN_USE = {"ResourceConflictException", "DependencyViolation"}
_TEARDOWN_S = 840.0


def _best_effort_delete(window, fn, interval_s=2, **kwargs):
    """Delete, returning on not-found and retrying only the in-use refusals (a still-PENDING connector,
    which can take up to 10 minutes to provision, or its ENIs still in the subnet/security group)
    inside one deadline shared by every teardown of the check, which fits the 900 s cleanup budget;
    every other error raises."""
    deadline = window.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    while True:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _NOT_FOUND:
                return
            if code not in _IN_USE or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _usable_zone(ec2):
    """The alphabetically-first available zone in the region. Network connectors with
    AssociatedComputeResourceTypes=MicroVm are only supported in a subset of AZs (us-west-2's
    usw2-az4 rejects them with InvalidParameterValueException), so an account's default-VPC AZ
    cannot be assumed to work.
    """
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )[
            "AvailabilityZones"
        ]
    )
    assert zones, "region offers no available availability zones"
    return zones[0]


def _setup_operator_role_and_vpc(ctx, name):
    """Create a dedicated VPC/subnet/security group and IAM role, rather than depending on the
    account's default VPC, which may not exist on a fresh account.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    az = _usable_zone(ec2)
    window: dict = {}

    vpc_id = ec2.create_vpc(CidrBlock="10.199.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort_delete(window, ec2.delete_vpc, VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.199.1.0/24", AvailabilityZone=az, TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort_delete(window, ec2.delete_subnet, SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda-core test",
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _best_effort_delete(window, ec2.delete_security_group, GroupId=sg_id))

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy, Tags=[{"Key": "Name", "Value": name}])
    role_arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not _attached():
        time.sleep(2)
    if not _attached():
        raise AssertionError("policy attachment did not become visible on the role within 30s")
    return {"subnet_id": subnet_id, "sg_id": sg_id, "role_arn": role_arn, "teardown_window": window}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
