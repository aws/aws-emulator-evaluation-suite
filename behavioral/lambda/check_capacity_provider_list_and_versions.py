"""capacity-provider-list-and-versions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "capacity-provider-list-and-versions"
GROUP = "state-machine"
SERVICES = ["lambda"]

_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCapacityProviders lists a new capacity provider, ListFunctionVersionsByCapacityProvider echoes
    its ARN with no versions, and after deletion it is unlisted and GetCapacityProvider is
    ResourceNotFoundException with the exact message."""
    lam = ctx.client("lambda")
    name, arn = _create_capacity_provider(ctx)

    assert _arn_in_list(lam, arn), "newly created capacity provider missing from ListCapacityProviders"

    versions = lam.list_function_versions_by_capacity_provider(CapacityProviderName=name)
    assert versions["CapacityProviderArn"] == arn, (
        f"expected ListFunctionVersionsByCapacityProvider to echo {arn!r}, got {versions['CapacityProviderArn']!r}"
    )
    assert versions.get("FunctionVersions", []) == [], (
        "expected no function versions for a freshly created capacity provider"
    )

    lam.delete_capacity_provider(CapacityProviderName=name)

    def _still_listed():
        return _arn_in_list(lam, arn)

    gone = _poll_until(_still_listed, lambda present: not present, timeout_s=120.0, interval_s=5.0)
    assert gone is False, "deleted capacity provider still present in ListCapacityProviders"

    try:
        lam.get_capacity_provider(CapacityProviderName=name)
        raise AssertionError("GetCapacityProvider on a deleted capacity provider unexpectedly succeeded")
    except lam.exceptions.ResourceNotFoundException as exc:
        message = exc.response["Error"]["Message"]
    expected = (
        f"Capacity provider not found: {arn}. Check that the ARN is correct and the "
        "capacity provider exists in this Region."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _arn_in_list(lam, arn: str) -> bool:
    # ListCapacityProviders' items carry no name field, only CapacityProviderArn: match on the
    # ARN the create call returned.
    marker = None
    while True:
        kwargs = {"MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp = lam.list_capacity_providers(**kwargs)
        for cp in resp.get("CapacityProviders", []):
            if cp["CapacityProviderArn"] == arn:
                return True
        marker = resp.get("NextMarker")
        if not marker:
            return False


def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cplv-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.82.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real lambda capacity provider list/versions behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cplvop-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN))
    return role_arn


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


def _create_capacity_provider(ctx):
    """Build VPC/IAM prerequisites in-check and create a capacity provider."""
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    operator_role_arn = _create_operator_role(ctx)

    cp_name = ctx.unique_name("sim2real-behav-cp2-")
    resp = _call_create_with_retry(
        lam,
        {
            "CapacityProviderName": cp_name,
            "VpcConfig": {"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
            "PermissionsConfig": {"CapacityProviderOperatorRoleArn": operator_role_arn},
            "InstanceRequirements": {"Architectures": ["x86_64"]},
        },
    )["CapacityProvider"]

    ctx.on_cleanup(lambda: _delete_cp_ignore(lam, cp_name))
    return cp_name, resp["CapacityProviderArn"]


def _delete_cp_ignore(lam, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        lam.delete_capacity_provider(CapacityProviderName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
