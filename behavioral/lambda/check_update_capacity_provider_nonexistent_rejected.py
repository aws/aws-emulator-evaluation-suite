"""update-capacity-provider-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]

_CP_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider and GetCapacityProvider on a never-created id return
    ResourceNotFoundException, not a generic 400, while the identical calls on a real capacity
    provider succeed and ListCapacityProviders keeps working."""
    lam = ctx.client("lambda")
    cp_name = _create_capacity_provider(ctx)
    missing_name = ctx.unique_name("sim2real-cp-missing-")

    # positive control: Get/Update succeed on the real capacity provider. GetCapacityProvider
    # and ListCapacityProviders never echo the name back as its own field — only the ARN, which
    # embeds it — so identity is confirmed through the ARN, not a nonexistent name field.
    real = lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"]
    assert real["CapacityProviderArn"].endswith(f":capacity-provider:{cp_name}"), real
    # PropagateTags (not CapacityProviderScalingConfig) is the update field under test: a
    # MaxVCpuCount change is independently subject to an account-relative "recommended
    # minimum" InstanceRequirements validation (confirmed on real AWS — rejected 10 as too
    # low with no fixed minimum stated), which would confound this existence check with a
    # param-validation error unrelated to what this check tests.
    updated = lam.update_capacity_provider(
        CapacityProviderName=cp_name,
        PropagateTags={"Mode": "None"},
    )["CapacityProvider"]
    assert updated["PropagateTags"]["Mode"] == "None", updated

    # negative: the identical calls fail, specifically, on an id that was never created
    missing_message = (
        f"Capacity provider not found: arn:aws:lambda:{ctx.region}:{ctx.account}:capacity-provider:"
        f"{missing_name}. Check that the ARN is correct and the capacity provider exists in this Region."
    )
    get_code, get_message = _error(lambda: lam.get_capacity_provider(CapacityProviderName=missing_name))
    assert get_code == "ResourceNotFoundException", get_code
    assert get_message == missing_message, f"unexpected GetCapacityProvider not-found message, got {get_message!r}"

    update_code, update_message = _error(
        lambda: lam.update_capacity_provider(
            CapacityProviderName=missing_name,
            PropagateTags={"Mode": "None"},
        )
    )
    assert update_code == "ResourceNotFoundException", update_code
    assert update_message == missing_message, (
        f"unexpected UpdateCapacityProvider not-found message, got {update_message!r}"
    )

    # the capacity-provider API surface itself is healthy: the real one is listed,
    # the nonexistent name is correctly absent
    listing = lam.list_capacity_providers()
    arns = [cp["CapacityProviderArn"] for cp in listing["CapacityProviders"]]
    assert any(arn.endswith(f":capacity-provider:{cp_name}") for arn in arns), arns
    assert not any(arn.endswith(f":capacity-provider:{missing_name}") for arn in arns), arns


# ===== helpers =====
def _error(fn):
    """The (code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.95.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda capacity-provider test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cp-op-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CP_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CP_MANAGED_POLICY_ARN))
    return role_arn


def _cp_state(lam, name):
    try:
        return lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _create_capacity_provider(ctx):
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    role_arn = _create_operator_role(ctx)
    name = ctx.unique_name("sim2real-cp-")

    def _try_create():
        try:
            lam.create_capacity_provider(
                CapacityProviderName=name,
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
                PermissionsConfig={"CapacityProviderOperatorRoleArn": role_arn},
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return False  # operator role not yet propagated
            raise

    _poll_until(_try_create, lambda ok: ok, timeout_s=120.0, interval_s=5.0)

    def _cleanup():
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ResourceConflictException"):
                raise
        _poll_until(lambda: _cp_state(lam, name), lambda s: s is None, timeout_s=600.0, interval_s=10.0)

    ctx.on_cleanup(_cleanup)
    _poll_until(lambda: _cp_state(lam, name), lambda s: s not in (None, "Pending"), timeout_s=600.0, interval_s=10.0)
    return name


# A resource in this VPC deletes asynchronously and its ENIs linger, so DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc retry DependencyViolation within one window shared by all of the
# check's network deletes, then raise naming the attached ENIs; every other error propagates.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
