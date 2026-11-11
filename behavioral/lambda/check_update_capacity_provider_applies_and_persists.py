"""update-capacity-provider-applies-and-persists."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-applies-and-persists"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider durably persists new scaling bounds, visible on a later GetCapacityProvider."""
    lam = ctx.client("lambda")
    net = _create_network(ctx)
    operator_role_arn = _create_operator_role(ctx)
    name = ctx.unique_name("sim2real-lambda-cp-")

    _create_capacity_provider(
        ctx,
        lam,
        name,
        net,
        operator_role_arn,
        scaling_config={"MaxVCpuCount": 32},
    )
    cp = _wait_cp_active(lam, name, timeout_s=600)
    assert cp["CapacityProviderScalingConfig"]["MaxVCpuCount"] == 32, (
        f"expected initial MaxVCpuCount=32, got {cp['CapacityProviderScalingConfig'].get('MaxVCpuCount')}"
    )

    lam.update_capacity_provider(
        CapacityProviderName=name,
        CapacityProviderScalingConfig={"MaxVCpuCount": 64},
    )

    # The update is accepted asynchronously (HTTP 202); poll a *fresh* GetCapacityProvider
    # call (not the UpdateCapacityProvider response echo) until the new bound is durably applied.
    deadline = time.monotonic() + 300
    applied = None
    state = None
    while time.monotonic() < deadline:
        got = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
        if got["State"] == "Failed":
            raise AssertionError(f"capacity provider transitioned to Failed: {got}")
        applied = got["CapacityProviderScalingConfig"]["MaxVCpuCount"]
        state = got["State"]
        if applied == 64 and state == "Active":
            return
        time.sleep(2)
    raise AssertionError(
        f"MaxVCpuCount never durably became 64 with State=Active (last saw MaxVCpuCount={applied}, State={state})"
    )


# ===== helpers =====


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.83.0.0/25",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-lambda-cp-sg-"),
        Description="sim2real lambda capacity provider test sg",
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": "sim2real-lambda-cp-sg"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return {"subnet_id": subnet_id, "sg_id": sg_id}


def _create_operator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cp-operator-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_capacity_provider(ctx, lam, name, net, operator_role_arn, scaling_config=None) -> None:
    kwargs = dict(
        CapacityProviderName=name,
        VpcConfig={"SubnetIds": [net["subnet_id"]], "SecurityGroupIds": [net["sg_id"]]},
        PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
        InstanceRequirements={"Architectures": ["x86_64"]},
    )
    if scaling_config:
        kwargs["CapacityProviderScalingConfig"] = scaling_config

    def _cleanup():
        _delete_capacity_provider(lam, name)

    # Retry briefly: the freshly-created operator role may not yet be assumable by Lambda.
    deadline = time.monotonic() + 60
    while True:
        try:
            lam.create_capacity_provider(**kwargs)
            ctx.on_cleanup(_cleanup)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _delete_capacity_provider(lam, name) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException":
                raise
            time.sleep(2)
    raise AssertionError(f"capacity provider {name} still in conflict after 120 s")


def _wait_cp_active(lam, name, timeout_s=600) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        cp = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
        last = cp
        if cp["State"] == "Active":
            return cp
        if cp["State"] == "Failed":
            raise AssertionError(f"capacity provider {name} transitioned to Failed: {cp}")
        time.sleep(2)
    raise AssertionError(f"capacity provider {name} never reached Active (last state: {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
