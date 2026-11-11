"""delete-capacity-provider-in-use-by-runtime-blocked."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-capacity-provider-in-use-by-runtime-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityProvider while an agent runtime is bound to it is refused with ValidationException and the exact
    attached-versions message and the provider does not enter DELETING; an unbound provider's delete answers DELETING
    and Get then answers ResourceNotFoundException "No capacity provider found with id <id>"."""
    bac = ctx.client("bedrock-agentcore-control")
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _create_network(ctx, ec2)
    role_arn = _create_agentcore_role(ctx)

    cp_name = _alnum(ctx, "s2rCap", 48)
    cp = _retry_transient_access_denied(
        lambda: bac.create_capacity_provider(
            name=cp_name,
            permissionsConfiguration={"capacityProviderOperatorRoleArn": role_arn},
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
    cp_id = cp["capacityProviderId"]
    cp_arn = cp["capacityProviderArn"]
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(bac, cp_id))
    ready = _poll(
        lambda: bac.get_capacity_provider(capacityProviderId=cp_id),
        lambda r: r["status"] not in ("CREATING",),
        timeout_s=240.0,
    )
    assert ready["status"] == "READY", f"capacity provider did not become READY: {ready['status']!r}"

    runtime_name = _alnum(ctx, "s2rArt", 48)
    runtime = bac.create_agent_runtime(
        agentRuntimeName=runtime_name,
        agentRuntimeArtifact={
            "containerConfiguration": {"containerUri": "public.ecr.aws/lambda/python:3.12"}
        },
        roleArn=role_arn,
        capacityProviderConfiguration={"capacityProviderArn": cp_arn},
    )
    runtime_id = runtime["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_runtime_and_wait(bac, runtime_id))
    runtime_ready = _poll(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=240.0,
    )
    assert runtime_ready["status"] == "READY", f"unexpected terminal status {runtime_ready['status']!r}"

    code, message = _error_detail(lambda: bac.delete_capacity_provider(capacityProviderId=cp_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    expected_message = (
        f"Cannot delete capacity provider '{cp_id}' because it still has attached agent runtime versions. "
        "Delete all attached agent runtime versions before deleting the capacity provider."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = bac.get_capacity_provider(capacityProviderId=cp_id)
    assert still["status"] != "DELETING", "capacity provider entered DELETING despite the blocked call"

    # Positive control: an unbound capacity provider deletes cleanly.
    _delete_runtime_and_wait(bac, runtime_id)
    cp2_name = _alnum(ctx, "s2rCap2", 48)
    cp2 = bac.create_capacity_provider(
        name=cp2_name,
        permissionsConfiguration={"capacityProviderOperatorRoleArn": role_arn},
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
    cp_id2 = cp2["capacityProviderId"]
    ctx.on_cleanup(lambda: _delete_capacity_provider_and_wait(bac, cp_id2))
    ready2 = _poll(
        lambda: bac.get_capacity_provider(capacityProviderId=cp_id2),
        lambda r: r["status"] not in ("CREATING",),
        timeout_s=240.0,
    )
    assert ready2["status"] == "READY", f"capacity provider did not become READY: {ready2['status']!r}"
    del_resp = bac.delete_capacity_provider(capacityProviderId=cp_id2)
    assert del_resp["status"] == "DELETING", "expected the unbound capacity provider delete to be accepted"

    # Terminal read: an independent GetCapacityProvider (not the delete call itself)
    # must show the unbound provider gone.
    gone_code, gone_message = _poll_gone(lambda: bac.get_capacity_provider(capacityProviderId=cp_id2))
    assert gone_code == "ResourceNotFoundException", (
        f"expected the unbound capacity provider to disappear, got {gone_code!r}"
    )
    expected_gone = f"No capacity provider found with id {cp_id2}"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"


def _alnum(ctx, prefix: str, maxlen: int) -> str:
    raw = ctx.unique_name(prefix)
    name = re.sub(r"[^A-Za-z0-9_]", "", raw)
    return name[:maxlen]


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=600.0, interval_s=10.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _delete_and_wait(read, delete, what, timeout_s=600.0, interval_s=10.0):
    """Delete once readable and out of a transitional state, then wait for not-found; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = read()["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status not in ("CREATING", "UPDATING", "DELETING"):
            try:
                delete()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s (status {status})")
        time.sleep(interval_s)


def _delete_runtime_and_wait(bac, runtime_id):
    _delete_and_wait(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda: bac.delete_agent_runtime(agentRuntimeId=runtime_id),
        f"agent runtime {runtime_id}",
    )


def _delete_capacity_provider_and_wait(bac, cp_id):
    _delete_and_wait(
        lambda: bac.get_capacity_provider(capacityProviderId=cp_id),
        lambda: bac.delete_capacity_provider(capacityProviderId=cp_id),
        f"capacity provider {cp_id}",
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_network(ctx, ec2):
    """Create a VPC, one subnet in an AZ that offers m5.large, and a security group; clean all up."""
    tag_spec = lambda kind: [{"ResourceType": kind, "Tags": [{"Key": "sim2real", "Value": CHECK}]}]  # noqa: E731
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    offerings = ec2.describe_instance_type_offerings(
        LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": ["m5.large"]}]
    )["InstanceTypeOfferings"]
    if not offerings:
        raise AssertionError("no availability zone in this region offers m5.large")
    az = sorted(o["Location"] for o in offerings)[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.42.1.0/24", AvailabilityZone=az, TagSpecifications=tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    sg_id = ec2.create_security_group(
        GroupName=_alnum(ctx, "sim2real-cap-sg", 64),
        Description="sim2real capacity provider check",
        VpcId=vpc_id,
        TagSpecifications=tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg_id)))
    return subnet_id, sg_id


def _retry_dependency(fn, timeout_s=600.0, interval_s=10.0) -> None:
    """Retry an EC2 delete while ENIs left by terminated capacity drain (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_agentcore_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _alnum(ctx, "s2rBacRole", 64)
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreRuntimeInstancesOperatorRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _retry_transient_access_denied(fn, timeout_s=90.0):
    """A freshly-created IAM role can take a few seconds to propagate before
    bedrock-agentcore-control can assume it; retry the initial create call while that resolves.
    Propagation delay surfaces either as AccessDeniedException or as a ValidationException
    whose message is the generic "Role validation failed for the operator role" (AgentCore
    synchronously test-assumes the role and cannot yet see a role that IAM has not propagated)."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            transient = code == "AccessDeniedException" or (
                code == "ValidationException" and "Role validation failed" in message
            )
            if not transient:
                raise
            last_err = e
            time.sleep(3.0)
    raise AssertionError(f"still failing role-assumption validation after {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
