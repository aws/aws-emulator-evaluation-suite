"""capacity-provider-scaling-value-precision-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "capacity-provider-scaling-value-precision-round-trip"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider's decimal scaling fields (max vCPU count, target-utilization
    percentage with fractional precision) come back byte-identical on GetCapacityProvider --
    no server-side rounding to an integer or coarser decimal grid."""
    lam = ctx.client("lambda")
    name, _arn = _create_capacity_provider(
        ctx,
        scaling_config={"MaxVCpuCount": 32, "ScalingMode": "Auto"},
    )

    # 47.125 == 47 + 1/8, exactly representable as an IEEE-754 double -- a mismatch here
    # can only be a server-side rounding/truncation bug, not float representation noise.
    # Empirically, a ScalingPolicies entry is only accepted when ScalingMode is "Manual"
    # ("Auto" rejects an explicit policy with InvalidParameterValueException).
    precise_target = 47.125
    lam.update_capacity_provider(
        CapacityProviderName=name,
        CapacityProviderScalingConfig={
            "MaxVCpuCount": 64,
            "ScalingMode": "Manual",
            "ScalingPolicies": [
                {
                    "PredefinedMetricType": "LambdaCapacityProviderAverageCPUUtilization",
                    "TargetValue": precise_target,
                }
            ],
        },
    )

    # UpdateCapacityProvider returns HTTP 202 (accepted, not applied) per the Smithy model, so the
    # new bound can lag a GetCapacityProvider issued right after it -- poll a bounded window for the
    # update to land instead of trusting a single immediate read.
    deadline = time.monotonic() + 120.0
    scaling = None
    while True:
        got = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
        scaling = got["CapacityProviderScalingConfig"]
        policies = scaling.get("ScalingPolicies") or []
        if scaling.get("MaxVCpuCount") == 64 and policies and policies[0].get("TargetValue") == precise_target:
            break
        if time.monotonic() > deadline:
            break
        time.sleep(5)

    assert scaling["MaxVCpuCount"] == 64, f"expected MaxVCpuCount=64, got {scaling['MaxVCpuCount']}"
    got_target = scaling["ScalingPolicies"][0]["TargetValue"]
    assert got_target == precise_target, f"expected TargetValue={precise_target!r}, got {got_target!r}"


# ===== helpers =====

def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real lambda managed-instances capacity provider sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cpop-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN))
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
    raise AssertionError(f"capacity provider {name} was not deleted within {timeout_s}s")


def _call_create_with_retry(lam, kwargs, timeout_s=180.0):
    # A freshly-created operator role can take a few seconds to propagate through IAM
    # before Lambda's cross-service assume-role check will accept it.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_capacity_provider(**kwargs)
        except lam.exceptions.InvalidParameterValueException as exc:
            if "operator role" not in str(exc) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_capacity_provider(ctx, scaling_config=None, capacity_provider_name=None):
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    operator_role_arn = _create_operator_role(ctx)
    name = capacity_provider_name or ctx.unique_name("sim2real-lambda-cp-")
    kwargs = {
        "CapacityProviderName": name,
        "VpcConfig": {"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        "PermissionsConfig": {"CapacityProviderOperatorRoleArn": operator_role_arn},
        "InstanceRequirements": {"Architectures": ["x86_64"]},
    }
    if scaling_config is not None:
        kwargs["CapacityProviderScalingConfig"] = scaling_config
    resp = _call_create_with_retry(lam, kwargs)

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
    return name, resp["CapacityProvider"]["CapacityProviderArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
