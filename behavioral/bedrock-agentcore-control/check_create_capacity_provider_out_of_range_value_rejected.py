"""create-capacity-provider-out-of-range-value-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-capacity-provider-out-of-range-value-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider with idleInstanceTimeout above the documented 1209600 s maximum
    is refused with ValidationException (not clamped) and leaves no provider, while the same
    request with an in-range value is accepted (positive control)."""
    client = ctx.client("bedrock-agentcore-control")
    subnet_id, sg_id = _default_vpc_network(ctx)
    role_arn = _create_operator_role(ctx)

    permissions_configuration = {"capacityProviderOperatorRoleArn": role_arn}

    def compute_configuration(idle_instance_timeout: int) -> dict:
        return {
            "ec2Configuration": {
                "launchTemplateSource": {
                    "launchParameters": {
                        "operatingSystem": "LINUX_X86_64",
                        "instanceRequirements": {"allowedInstanceTypes": ["m5.large"]},
                    }
                },
                "vpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id]},
                "lifecycleConfiguration": {"idleInstanceTimeout": idle_instance_timeout},
            }
        }

    bad_name = _pattern_safe_name(ctx, "sim2realcprange")
    code, message = _error_detail(
        lambda: _retry_role_propagation(
            lambda: client.create_capacity_provider(
                name=bad_name,
                permissionsConfiguration=permissions_configuration,
                # Documented Valid Range for idleInstanceTimeout is 60-1209600 seconds.
                computeConfiguration=compute_configuration(1209601),
            )
        )
    )
    if code in ("ResourceNotFoundException", "AccessDeniedException") or (
        code == "ValidationException"
        and any(
            s in (message or "")
            for s in ("not supported in region", "Role validation failed")
        )
    ):
        raise AssertionError(
            f"CreateCapacityProvider rejected the real subnet/security-group/role/instance-type "
            f"setup itself ({code}: {message}) before reaching the idleInstanceTimeout range "
            "check; this environment's shared network VPC/IAM/instance-type availability isn't usable "
            "to isolate the range-only signal."
        )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    expected_message = (
        "validation error detected. Value at "
        "'/computeConfiguration/ec2Configuration/lifecycleConfiguration/idleInstanceTimeout' "
        "failed to satisfy constraint: Member must be between 60 and 1209600, inclusive"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no capacity provider under that name exists.
    assert not _capacity_provider_name_exists(client, bad_name), (
        f"capacity provider {bad_name} exists despite the out-of-range rejected create"
    )

    # Positive control: the identical request with an in-range value is accepted.
    # Guard with the same role-propagation retry -- the operator role's IAM
    # policy attachment may still be propagating even after the first call.
    good_name = _pattern_safe_name(ctx, "sim2realcprangeok")
    try:
        _retry_role_propagation(
            lambda: client.create_capacity_provider(
                name=good_name,
                permissionsConfiguration=permissions_configuration,
                computeConfiguration=compute_configuration(900),
            )
        )
    except ClientError as err:
        raise AssertionError(f"expected the in-range create to succeed, got {err}") from err
    created = client.get_capacity_provider(capacityProviderId=_capacity_provider_id(client, good_name))
    ctx.on_cleanup(lambda: _best_effort_delete_capacity_provider(client, created["capacityProviderId"]))
    assert created["name"] == good_name, (
        f"expected the created capacity provider's name to be {good_name}, got {created['name']!r}"
    )


# ===== helpers =====
def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
            "subnet + security group for an isolated idleInstanceTimeout range check"
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
    role_name = _iam_safe_name(ctx, "capop")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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


def _capacity_provider_name_exists(client, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_capacity_providers(**kwargs)
        for item in page.get("capacityProviders", []):
            if item.get("name") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


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
