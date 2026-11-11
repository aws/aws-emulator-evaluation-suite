"""capacity-provider-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A capacity provider (one m5.large) goes CREATING to READY, UpdateCapacityProvider returns it to READY with the
    new description, and after DeleteCapacityProvider GetCapacityProvider answers ResourceNotFoundException "No
    capacity provider found with id <id>"."""
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _default_subnet_and_sg(ctx, ec2)

    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "cp")
    name = _safe_name(ctx, "sim2realcp")

    compute_configuration = {
        "ec2Configuration": {
            "launchTemplateSource": {
                "launchParameters": {
                    "operatingSystem": "LINUX_X86_64",
                    "instanceRequirements": {"allowedInstanceTypes": ["m5.large"]},
                }
            },
            "vpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id]},
        }
    }

    create_resp = _retry_until_role_usable(
        lambda: bac.create_capacity_provider(
            name=name,
            permissionsConfiguration={"capacityProviderOperatorRoleArn": role_arn},
            computeConfiguration=compute_configuration,
        )
    )
    cp_id = create_resp["capacityProviderId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: bac.delete_capacity_provider(capacityProviderId=cp_id))
    )

    cp = _poll_until(
        lambda: bac.get_capacity_provider(capacityProviderId=cp_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=420.0,
        interval_s=10.0,
    )
    assert cp["status"] == "READY", f"unexpected terminal status {cp['status']!r}"

    bac.update_capacity_provider(
        capacityProviderId=cp_id, description={"optionalValue": "sim2real-updated"}
    )
    cp2 = _poll_until(
        lambda: bac.get_capacity_provider(capacityProviderId=cp_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert cp2["status"] == "READY", f"unexpected terminal status {cp2['status']!r}"
    assert cp2["description"] == "sim2real-updated", (
        f"expected description 'sim2real-updated', got {cp2.get('description')!r}"
    )

    bac.delete_capacity_provider(capacityProviderId=cp_id)
    code, message = _error_detail(
        lambda: bac.get_capacity_provider(capacityProviderId=cp_id), wait_s=300.0, interval_s=10.0
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"No capacity provider found with id {cp_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error_detail(fn, *, wait_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn raises. While fn still succeeds it is
    retried until wait_s elapses; a success at the deadline raises AssertionError."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _default_subnet_and_sg(ctx, ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for capacity provider networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for capacity provider networking")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group available")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_agentcore_execution_role(ctx, name_hint):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-bac-{name_hint}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
