"""update-capacity-provider-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller whose policy explicitly denies lambda:UpdateCapacityProvider (but allows every
    other lambda: action) is rejected with AccessDeniedException, the capacity provider's config
    is left untouched, and the same call succeeds for a caller with full permissions."""
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
    _wait_cp_active(lam, name, timeout_s=600)

    restricted_lambda, denied_arn = _create_denied_caller(ctx, lam)
    cp_arn = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]["CapacityProviderArn"]

    # (a) the specific error code and message
    code, message = _error(
        lambda: restricted_lambda.update_capacity_provider(
            CapacityProviderName=name,
            CapacityProviderScalingConfig={"MaxVCpuCount": 48},
        )
    )
    assert code == "AccessDeniedException", (
        f"explicit-deny caller must be rejected with AccessDeniedException, got code={code!r}"
    )
    assert message == (
        f"User: {denied_arn} is not authorized to perform: lambda:UpdateCapacityProvider on "
        f"resource: {cp_arn} with an explicit deny in an identity-based policy"
    ), f"unexpected AccessDenied message, got {message!r}"

    # (b) the effect is absent: the scaling config was NOT changed by the denied call
    cp = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
    applied_after_denial = cp["CapacityProviderScalingConfig"]["MaxVCpuCount"]
    assert applied_after_denial == 32, (
        f"denied update must not change the scaling config, but MaxVCpuCount is now "
        f"{applied_after_denial} (expected unchanged 32)"
    )

    # (c) positive control: the same call, with full permissions, succeeds and persists
    lam.update_capacity_provider(
        CapacityProviderName=name,
        CapacityProviderScalingConfig={"MaxVCpuCount": 48},
    )
    deadline = time.monotonic() + 300
    applied = None
    while time.monotonic() < deadline:
        got = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
        applied = got["CapacityProviderScalingConfig"]["MaxVCpuCount"]
        if applied == 48:
            return
        time.sleep(2)
    raise AssertionError(f"positive-control update never persisted (last saw {applied})")


def _create_denied_caller(ctx, lam):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-lambda-cp-denied-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-lambda-cp-denied-pol-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "lambda:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "lambda:UpdateCapacityProvider", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # Poll assume-role + a read-only, allowed call until the freshly-attached policy is usable.
    # (IAM changes are eventually consistent; explicit Deny/Allow statements in the same policy
    # document are evaluated together, so once the Allow half is visible the Deny half is too.)
    deadline = time.monotonic() + 60
    while True:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-denied-test")
            creds = assumed["Credentials"]
            restricted = ctx.client(
                "lambda",
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
            restricted.list_capacity_providers()
            return restricted, assumed["AssumedRoleUser"]["Arn"]
        except ClientError:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


# ===== helpers =====


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target ACCEPTING a call real AWS denies is the strongest signal available
    and must not be reported as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the explicit-deny caller's call to be rejected, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.87.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.87.0.0/25",
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
