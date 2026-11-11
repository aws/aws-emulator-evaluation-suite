"""network-connector-e2e-create-transitions-pending-to-active."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-e2e-create-transitions-pending-to-active"
GROUP = "e2e"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"
_ROLE_PROPAGATION_WAIT_S = 120.0
_TEARDOWN_WAIT_S = 600.0
_GONE_WAIT_S = 300.0
# IAM propagation lag surfaces as either message, depending on whether the service first
# assumes the role or authorizes its EC2 calls; both are transient for this role.
_ROLE_PROPAGATION_MESSAGES = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole",
    "invalid ConnectorOperatorRole permissions",
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkConnector returns a connector in PENDING that becomes ACTIVE, and Get reports
    the same Id and Arn the create returned.
    """
    lc = ctx.client("lambda-core")
    infra = _setup_operator_role_and_vpc(ctx)

    name = ctx.unique_name("sim2real-lnc-")
    created = _create_connector(
        lc,
        Name=name,
        Configuration=_vpc_egress_config([infra["subnet_id"]], [infra["sg_id"]]),
        OperatorRole=infra["role_arn"],
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_connector(lc, connector_id))

    assert created["State"] == "PENDING", f"expected PENDING immediately after create, got {created['State']}"

    final = _poll_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda resp: resp["State"] in ("ACTIVE", "FAILED"),
        timeout_s=720,
        interval_s=15,
    )
    assert final["State"] == "ACTIVE", (
        f"connector did not reach ACTIVE, State={final['State']} "
        f"StateReasonCode={final.get('StateReasonCode')} StateReason={final.get('StateReason')}"
    )
    assert final["Id"] == connector_id, f"the independent Get read Id={final['Id']!r}, expected {connector_id!r}"
    assert final["Arn"] == created["Arn"], (
        f"the independent Get read Arn={final['Arn']!r}, expected {created['Arn']!r}"
    )

    # Delete in the body: its ENIs hold the subnet, security group and VPC until the delete
    # completes, which outlasts the cleanup budget.
    _delete_connector(lc, connector_id)


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


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_connector(lc, connector_id):
    """Delete, retrying ResourceConflictException while PENDING, then wait for Get to 404; the
    connector's ENIs block network teardown with DependencyViolation until then."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            lc.delete_network_connector(Identifier=connector_id)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    gone = time.monotonic() + _GONE_WAIT_S
    while time.monotonic() < gone:
        try:
            lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"connector {connector_id!r} still answered Get {_GONE_WAIT_S}s after delete")


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejections; propagation to
    lambda-core exposes no pollable condition."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            propagating = any(m in message for m in _ROLE_PROPAGATION_MESSAGES)
            if not propagating or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _usable_zones(ec2, want):
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
    assert len(zones) >= want, f"region offers only {zones!r}, need {want} available zones"
    return zones[:want]


def _setup_operator_role_and_vpc(ctx, extra_security_group=False):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lnc-")

    az = _usable_zones(ec2, 1)[0]

    vpc_id = ec2.create_vpc(CidrBlock="10.199.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.199.1.0/24", AvailabilityZone=az, TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda-core test",
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    sg_id2 = None
    if extra_security_group:
        sg_id2 = ec2.create_security_group(
            VpcId=vpc_id,
            GroupName=f"{name}-2",
            Description="sim2real lambda-core test 2",
            TagSpecifications=[_tag_spec("security-group", f"{name}-2")],
        )["GroupId"]
        ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id2))

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)
    role_arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    _poll_until(_attached, lambda ok: ok, timeout_s=30, interval_s=2)

    return {"subnet_id": subnet_id, "sg_id": sg_id, "sg_id2": sg_id2, "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
