"""update-capacity-provider-concurrent-conflicting-writes."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-concurrent-conflicting-writes"
GROUP = "concurrency"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateCapacityProvider calls both succeed (the update is applied
    asynchronously with no synchronous conflict detection), and the persisted value is exactly one
    of the two submitted.
    """
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

    outcome = None
    all_attempts = []
    # Retry a few times to rule out a one-off transient error on either call.
    for attempt in range(3):
        _wait_cp_active(lam, name, timeout_s=120)
        candidate_a, candidate_b = 40 + attempt, 48 + attempt
        results = _fire_concurrent_updates(lam, name, candidate_a, candidate_b)
        all_attempts.append(results)
        oks = [r for r in results.values() if r[0] == "ok"]
        if len(oks) == 2:
            outcome = (results, {candidate_a, candidate_b})
            break

    assert outcome is not None, (
        f"expected both concurrent UpdateCapacityProvider calls to succeed (real AWS applies "
        f"them asynchronously with no synchronous conflict detection) across retries: "
        f"{all_attempts}"
    )
    _, candidates = outcome

    cp = _wait_cp_active(lam, name, timeout_s=120)
    persisted = cp["CapacityProviderScalingConfig"]["MaxVCpuCount"]
    assert persisted in candidates, (
        f"persisted MaxVCpuCount ({persisted}) is neither of the two concurrently-submitted "
        f"values ({candidates}) — writes were corrupted rather than serialized"
    )


def _fire_concurrent_updates(lam, name, value_a, value_b) -> dict:
    barrier = threading.Barrier(2)
    results = {}

    def _do(key, value):
        barrier.wait()
        try:
            lam.update_capacity_provider(
                CapacityProviderName=name,
                CapacityProviderScalingConfig={"MaxVCpuCount": value},
            )
            results[key] = ("ok", value)
        except ClientError as e:
            results[key] = ("error", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(_do, "a", value_a)
        f2 = ex.submit(_do, "b", value_b)
        f1.result()
        f2.result()
    return results



def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.85.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.85.0.0/25",
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
    while True:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


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
        time.sleep(5)
    raise AssertionError(f"capacity provider {name} never reached Active (last state: {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
