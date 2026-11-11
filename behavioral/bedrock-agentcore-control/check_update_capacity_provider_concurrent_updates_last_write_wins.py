"""update-capacity-provider-concurrent-updates-last-write-wins."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-concurrent-updates-last-write-wins"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two back-to-back UpdateCapacityProvider calls on a READY capacity provider both answer UPDATING, and once it
    is READY again its description is the second request's value "scale-b"."""
    bac = ctx.client("bedrock-agentcore-control")
    ec2 = ctx.client("ec2")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision capacity provider compute")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to provision capacity provider compute")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    role_arn = _create_capacity_operator_role(ctx)

    cp = _retry_role_propagation(
        lambda: bac.create_capacity_provider(
            name=_alnum_name(ctx, "sim2realcp"),
            permissionsConfiguration={"capacityProviderOperatorRoleArn": role_arn},
            tags={"sim2real": "true"},
            computeConfiguration={
                "ec2Configuration": {
                    "launchTemplateSource": {
                        "launchParameters": {
                            "operatingSystem": "LINUX_X86_64",
                            "instanceRequirements": {"allowedInstanceTypes": ["m5.large"]},
                        }
                    },
                    "vpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id]},
                }
            },
        )
    )
    capacity_provider_id = cp["capacityProviderId"]
    ctx.on_cleanup(lambda: bac.delete_capacity_provider(capacityProviderId=capacity_provider_id))
    _poll_until(
        lambda: bac.get_capacity_provider(capacityProviderId=capacity_provider_id),
        lambda r: r["status"] in ("READY", "CREATE_FAILED"),
        timeout_s=300,
    )
    setup = bac.get_capacity_provider(capacityProviderId=capacity_provider_id)
    assert setup["status"] == "READY", f"capacity provider setup failed: {setup}"

    def _update(desc):
        try:
            return bac.update_capacity_provider(
                capacityProviderId=capacity_provider_id, description={"optionalValue": desc}
            )
        except ClientError as exc:
            raise AssertionError(
                f"expected UpdateCapacityProvider(description={desc!r}) to be accepted, got "
                f"{exc.response['Error']['Code']}: {exc.response['Error'].get('Message')}"
            ) from exc

    r1 = _update("scale-a")
    assert r1["status"] == "UPDATING", f"expected the first update to be accepted as UPDATING, got {r1!r}"

    r2 = _update("scale-b")
    assert r2["status"] == "UPDATING", (
        "expected the second update -- issued while the first was still UPDATING -- to "
        f"also be accepted rather than rejected with a conflict, got {r2!r}"
    )

    final = _poll_until(
        lambda: bac.get_capacity_provider(capacityProviderId=capacity_provider_id),
        lambda r: r["status"] == "READY",
        timeout_s=300,
    )
    assert final["description"] == "scale-b", (
        "expected the last-issued update ('scale-b') to win once the capacity provider "
        f"settles (last-write-wins), got {final.get('description')!r}"
    )


def _alnum_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _create_capacity_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bac-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreRuntimeInstancesOperatorRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            return role_arn
        except ClientError:
            time.sleep(2)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """bedrock-agentcore-control validates the operator role's existence/trust policy
    at CreateCapacityProvider time; a role/policy just created via IAM can still be
    unpropagated there, and the call fails with ValidationException: "Role validation
    failed for the operator role" until it catches up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationException" and "Role validation failed" in err.get("Message", ""):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
