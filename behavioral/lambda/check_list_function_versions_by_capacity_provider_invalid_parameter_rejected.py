"""list-function-versions-by-capacity-provider-invalid-parameter-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-function-versions-by-capacity-provider-invalid-parameter-rejected"
GROUP = "error-semantics"
# Capacity-provider teardown deadline, inside the suite's 900 s cleanup budget.
_CLEANUP_BUDGET_S = 840.0
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListFunctionVersionsByCapacityProvider with a malformed pagination Marker is rejected with
    InvalidParameterValueException; the same call with no Marker on the same provider still
    succeeds (positive control)."""
    lam = ctx.client("lambda")
    net = _create_network(ctx)
    operator_role_arn = _create_operator_role(ctx)
    name = ctx.unique_name("sim2real-lambda-cp-")

    _create_capacity_provider(ctx, lam, name, net, operator_role_arn)
    _wait_cp_active(lam, name, timeout_s=600)

    code, code_msg = _error(
        lambda: lam.list_function_versions_by_capacity_provider(
            CapacityProviderName=name, Marker="not-a-real-pagination-token!!"
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a malformed Marker, got {code!r}"
    )
    expected_msg = (
        "The marker value isn't valid: not-a-real-pagination-token!!. Specify a valid marker value "
        "and try again."
    )
    assert code_msg == expected_msg, (
        f"expected the exact 'InvalidParameterValueException' message, got {code_msg!r}"
    )

    # Positive control: the same operation on the same, real provider succeeds without a marker.
    resp = lam.list_function_versions_by_capacity_provider(CapacityProviderName=name)
    assert resp["FunctionVersions"] == [], (
        f"expected no function versions for freshly-created provider {name!r}, got {resp['FunctionVersions']!r}"
    )


def _error(fn):
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.86.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.86.0.0/25",
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

    deadline = time.monotonic() + min(60.0, ctx.time_left() or 60.0)
    while True:
        try:
            lam.create_capacity_provider(**kwargs)
            ctx.on_cleanup(_cleanup)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_capacity_provider(lam, name) -> None:
    """Delete, then poll until gone: the VPC teardowns that run next need its network interfaces gone."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"capacity provider {name} was not deleted within {_CLEANUP_BUDGET_S:.0f}s")


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
