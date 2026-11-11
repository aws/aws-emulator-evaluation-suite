"""create-capacity-provider-duplicate-name-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-capacity-provider-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateCapacityProvider reusing an existing name is accepted, not refused with
    ConflictException, and both same-named providers reach READY as distinct resources:
    capacityProviderId, not name, is the identity despite the documented uniqueness."""
    client = ctx.client("bedrock-agentcore-control")
    subnet_id, sg_id = _default_vpc_network(ctx)
    role_arn = _create_operator_role(ctx)

    permissions_configuration = {"capacityProviderOperatorRoleArn": role_arn}
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

    def _create(name: str):
        return _retry_role_propagation(
            lambda: client.create_capacity_provider(
                name=name,
                permissionsConfiguration=permissions_configuration,
                computeConfiguration=compute_configuration,
                tags={"sim2real": CHECK},
            )
        )

    # Positive control: the first create with a fresh name succeeds.
    name = _pattern_safe_name(ctx, "sim2realcpdup")
    try:
        _create(name)
    except ClientError as err:
        raise AssertionError(
            f"CreateCapacityProvider rejected the real subnet/security-group/role setup "
            f"itself ({err}) before the duplicate-name conflict could be "
            "tested; this environment's shared network VPC/IAM setup isn't usable to isolate "
            "the conflict signal."
        ) from err
    first_id = _capacity_provider_id(client, name)
    ctx.on_cleanup(lambda: _best_effort_delete_capacity_provider(client, first_id))

    # Reuse the identical name. Real AWS accepts this rather than rejecting it: it
    # provisions a second, independently-identified resource under the same name.
    try:
        client.create_capacity_provider(
            name=name,
            permissionsConfiguration=permissions_configuration,
            computeConfiguration=compute_configuration,
            tags={"sim2real": CHECK},
        )
    except ClientError as err:
        raise AssertionError(
            f"expected CreateCapacityProvider to accept the reused name (real AWS does not "
            f"enforce name uniqueness), got {err}"
        ) from err

    # Effect present: exactly two distinct capacityProviderIds now share the name.
    matched_ids = _capacity_provider_ids(client, name)
    for cid in matched_ids:
        if cid != first_id:
            ctx.on_cleanup(lambda cid=cid: _best_effort_delete_capacity_provider(client, cid))
    assert len(matched_ids) == 2, f"expected exactly 2 capacity providers named {name!r}, found {matched_ids}"
    second_id = next(cid for cid in matched_ids if cid != first_id)

    # Both must reach a terminal state -- the second is a fully independent resource,
    # not a failed/no-op echo of the first.
    first_final = _poll_until_terminal(client, first_id)
    second_final = _poll_until_terminal(client, second_id)
    assert first_final["status"] == "READY", f"expected {first_id} to reach READY, got {first_final}"
    assert second_final["status"] == "READY", f"expected {second_id} (the same-named reuse) to reach READY, got {second_final}"

    # Terminal read: independent of the create call, at the destination. Both ids
    # resolve to distinct resources that both report the shared name.
    assert first_final["name"] == name and second_final["name"] == name, (
        f"expected both {first_id} and {second_id} to report name {name!r}, "
        f"got {first_final['name']!r} and {second_final['name']!r}"
    )
    assert first_final["capacityProviderArn"] != second_final["capacityProviderArn"], (
        "expected the two same-named capacity providers to be distinct resources, "
        f"got identical ARN {first_final['capacityProviderArn']!r}"
    )


# ===== helpers =====
def _poll_until_terminal(client, capacity_provider_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_capacity_provider(capacityProviderId=capacity_provider_id)
        if last["status"] in ("READY", "CREATE_FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{capacity_provider_id} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """Call fn() and return its response. A freshly created/attached IAM role/policy may not
    have propagated yet, so a role-validation ValidationException is retried until timeout_s;
    any other refusal, or the last role-validation one, is raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            error = err.response["Error"]
            role_pending = error["Code"] == "ValidationException" and "Role validation failed" in (
                error.get("Message") or ""
            )
            if not role_pending or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "c" + safe
    return safe[:48]


def _iam_safe_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2real-behav-{suffix}-")
    safe = "".join(c for c in raw if c.isalnum() or c in "+=,.@_-")
    return safe[:64]


def _default_vpc_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(
            "no shared network VPC is available in this account/region to source a real "
            "subnet + security group for the duplicate-name conflict check"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"shared network {vpc_id} has no subnets to use for this check")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"shared network {vpc_id} has no default security group to use for this check")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_operator_role(ctx) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = _iam_safe_name(ctx, "capdup")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))
    policy_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreRuntimeInstancesOperatorRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _best_effort_detach_policy(iam, role_name, policy_arn))
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _best_effort_detach_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _capacity_provider_id(client, name: str) -> str:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_capacity_providers(**kwargs)
        for item in page.get("capacityProviders", []):
            if item.get("name") == name:
                return item["capacityProviderId"]
        next_token = page.get("nextToken")
        if not next_token:
            raise AssertionError(f"capacity provider named {name} not found via list_capacity_providers")


def _capacity_provider_ids(client, name: str) -> list[str]:
    """Every capacityProviderId named name, across all ListCapacityProviders pages."""
    found: set[str] = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_capacity_providers(**kwargs)
        found.update(
            item["capacityProviderId"]
            for item in page.get("capacityProviders", [])
            if item.get("name") == name
        )
        next_token = page.get("nextToken")
        if not next_token:
            return sorted(found)


def _best_effort_delete_capacity_provider(client, capacity_provider_id: str) -> None:
    # A provider still settling refuses deletion with a conflict: retry those codes only.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            client.delete_capacity_provider(capacityProviderId=capacity_provider_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "RetryableConflictException"):
                raise
            time.sleep(2)
    client.delete_capacity_provider(capacityProviderId=capacity_provider_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
