"""list-capacity-providers-stable-ordering."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "list-capacity-providers-stable-ordering"
GROUP = "ordering"
SERVICES = ["lambda"]

_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCapacityProviders returns a stable, deterministic order across repeated calls,
    and paginating with MaxItems=1 yields the identical relative order as a single
    unpaginated call (order need not be creation-time -- only self-consistent)."""
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    operator_role_arn = _create_operator_role(ctx)

    arns = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-lambda-cp-ord{i}-")
        arn = _create_capacity_provider_with_infra(
            ctx, subnet_id, sg_id, operator_role_arn, name
        )
        arns.append(arn)
        time.sleep(2)  # ensure strictly distinct creation timestamps between the three

    def _list_all(**kwargs):
        items = []
        marker = None
        while True:
            params = dict(kwargs)
            if marker:
                params["Marker"] = marker
            resp = lam.list_capacity_providers(**params)
            items.extend(resp["CapacityProviders"])
            marker = resp.get("NextMarker")
            if not marker:
                break
        return items

    arn_set = set(arns)

    # A freshly-created capacity provider can lag ListCapacityProviders by a few seconds on real
    # AWS, so wait for all three to become visible before asserting anything about their order.
    deadline = time.monotonic() + 120.0
    first = [
        cp["CapacityProviderArn"]
        for cp in _list_all(MaxItems=50)
        if cp["CapacityProviderArn"] in arn_set
    ]
    while set(first) != arn_set and time.monotonic() < deadline:
        time.sleep(5)
        first = [
            cp["CapacityProviderArn"]
            for cp in _list_all(MaxItems=50)
            if cp["CapacityProviderArn"] in arn_set
        ]
    assert sorted(first) == sorted(arns), (
        f"expected to see all created providers {arns}, got {first}"
    )

    second = [
        cp["CapacityProviderArn"]
        for cp in _list_all(MaxItems=50)
        if cp["CapacityProviderArn"] in arn_set
    ]
    assert second == first, (
        "ListCapacityProviders order changed between two consecutive calls"
    )

    paged = [
        cp["CapacityProviderArn"]
        for cp in _list_all(MaxItems=1)
        if cp["CapacityProviderArn"] in arn_set
    ]
    assert paged == first, (
        "paginated (MaxItems=1) ListCapacityProviders order differs from unpaginated order"
    )


# ===== helpers =====


def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.80.1.0/24",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real lambda managed-instances capacity provider sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cpop-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN
        )
    )
    return role_arn


def _wait_for_capacity_provider_gone(ctx, name, timeout_s=900.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except lam.exceptions.ResourceNotFoundException:
            return
        time.sleep(2)
    raise AssertionError(
        f"capacity provider {name} was not deleted within {timeout_s}s"
    )


def _call_create_with_retry(lam, kwargs, timeout_s=180.0):
    # A freshly-created operator role can take a few seconds to propagate through IAM
    # before Lambda's cross-service assume-role check will accept it.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_capacity_provider(**kwargs)
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_capacity_provider_with_infra(
    ctx, subnet_id, sg_id, operator_role_arn, name
):
    lam = ctx.client("lambda")
    resp = _call_create_with_retry(
        lam,
        {
            "CapacityProviderName": name,
            "VpcConfig": {"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
            "PermissionsConfig": {"CapacityProviderOperatorRoleArn": operator_role_arn},
            "InstanceRequirements": {"Architectures": ["x86_64"]},
        },
    )

    def _cleanup():
        deadline = time.monotonic() + 840.0
        while True:
            try:
                lam.delete_capacity_provider(CapacityProviderName=name)
                break
            except lam.exceptions.ResourceNotFoundException:
                return
            except lam.exceptions.ResourceConflictException:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)
        _wait_for_capacity_provider_gone(ctx, name, timeout_s=max(1.0, deadline - time.monotonic()))

    ctx.on_cleanup(_cleanup)
    return resp["CapacityProvider"]["CapacityProviderArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
