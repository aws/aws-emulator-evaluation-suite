"""network-connector-create-nonexistent-subnet-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-create-nonexistent-subnet-rejected"
GROUP = "state"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"

_ROLE_PROPAGATION_WAIT_S = 120.0
# Async FAILED reason when the operator role's permissions have not propagated yet.
_PERMISSION_FAILED_REASON = "The operator role does not have sufficient permissions to manage network interfaces."
_PERMISSION_RETRY_S = 300.0
# Two distinct transient messages, depending on which propagation lags: the trust policy
# (assume-role, checked first) or the attached permissions policy (checked second).
_TRANSIENT_ROLE_MESSAGES = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role.",
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions",
)


def _create_connector(lc, **kwargs):
    """IAM role/policy propagation exposes no pollable condition; the bounded retry on the
    exact transient messages is what makes this correct, not a wait."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            transient = any(m in message for m in _TRANSIENT_ROLE_MESSAGES)
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(2)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNetworkConnector rejects a non-existent subnet at call time with
    InvalidParameterValueException and creates no connector; a real subnet reaches ACTIVE."""
    lc = ctx.client("lambda-core")
    infra = _setup_operator_role_and_vpc(ctx)
    name = ctx.unique_name("sim2real-lnc-")

    control_final = _active_control(ctx, lc, name, infra)
    assert control_final["State"] == "ACTIVE", (
        f"positive control with a real subnet expected ACTIVE, got {control_final['State']} "
        f"reason={control_final.get('StateReason')}"
    )

    # Valid format ("subnet-" + 17 hex chars) but guaranteed not to exist. The positive control
    # above already warmed OperatorRole's trust+permissions propagation on this exact role, so
    # the rejection below is never confused with the transient role-propagation messages.
    bogus_subnet_id = "subnet-" + uuid.uuid4().hex[:17]
    bogus_name = name + "-bogus"

    code, message = _error(
        lambda: lc.create_network_connector(
            Name=bogus_name,
            Configuration=_vpc_egress_config([bogus_subnet_id], [infra["sg_id"]]),
            OperatorRole=infra["role_arn"],
        )
    )
    assert code == "InvalidParameterValueException", (
        f"a non-existent subnet raised {code!r} ({message!r}), expected InvalidParameterValueException"
    )
    assert message == (
        "Error occurred while DescribeSubnets. EC2 Error Code: InvalidSubnetID.NotFound. "
        f"EC2 Error Message: The subnet ID '{bogus_subnet_id}' does not exist"
    ), (
        f"expected the rejection to name the missing subnet, got: {message!r}"
    )

    listing = lc.list_network_connectors(MaxItems=100)
    matching = [c for c in listing["NetworkConnectors"] if c["Name"] == bogus_name]
    assert not matching, "a synchronously-rejected create must not have persisted a connector"


def _active_control(ctx, lc, name, infra):
    """Create the positive-control connector and wait for ACTIVE or FAILED. A FAILED connector
    with the operator-role permission reason is an IAM-propagation race: delete it and retry."""
    deadline = time.monotonic() + _PERMISSION_RETRY_S
    attempt = 0
    while True:
        control = _create_connector(
            lc,
            Name=f"{name}-ctl{attempt}",
            Configuration=_vpc_egress_config([infra["subnet_id"]], [infra["sg_id"]]),
            OperatorRole=infra["role_arn"],
        )
        control_id = control["Id"]
        ctx.on_cleanup(lambda c=control_id: _delete_connector(lc, c))
        assert control["State"] == "PENDING", f"expected PENDING on create, got {control['State']}"
        final = _poll_until(
            lambda: lc.get_network_connector(Identifier=control_id),
            lambda resp: resp["State"] in ("ACTIVE", "FAILED"),
            timeout_s=min(720.0, max(1.0, (ctx.time_left() or 720.0) - 60.0)),
            interval_s=2.0,
        )
        if (final["State"] != "FAILED" or final.get("StateReason") != _PERMISSION_FAILED_REASON
                or time.monotonic() >= deadline):
            return final
        _delete_connector(lc, control_id)
        attempt += 1


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _vpc_egress_config(subnet_ids, sg_ids=None, protocol="IPv4"):
    cfg = {
        "VpcEgressConfiguration": {
            "SubnetIds": subnet_ids,
            "NetworkProtocol": protocol,
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }
    if sg_ids:
        cfg["VpcEgressConfiguration"]["SecurityGroupIds"] = sg_ids
    return cfg


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_connector(lc, connector_id, timeout_s=480):
    """Delete, then wait until the connector is gone: it releases its ENIs asynchronously and needs
    the operator role until then, so the role and network teardowns must run after it."""
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"network connector {connector_id} not gone within {timeout_s}s (last={last!r})")


def _delete_in_use(fn, timeout_s=300):
    """Retry a network delete on DependencyViolation (ENIs still releasing); raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _usable_zone(ec2) -> str:
    """First available AZ in sorted order. Not every AZ supports the MicroVm compute type
    (e.g. usw2-az4), and CreateNetworkConnector rejects a subnet there at call time."""
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    )
    assert zones, "region offers no available availability zones"
    return zones[0]


def _setup_operator_role_and_vpc(ctx, extra_security_group=False):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lnc-")

    vpc_id = ec2.create_vpc(CidrBlock="10.199.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_in_use(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.199.1.0/24",
        AvailabilityZone=_usable_zone(ec2),
        TagSpecifications=[_tag_spec("subnet", name)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_in_use(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda-core test",
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_in_use(lambda: ec2.delete_security_group(GroupId=sg_id)))

    sg_id2 = None
    if extra_security_group:
        sg_id2 = ec2.create_security_group(
            VpcId=vpc_id,
            GroupName=f"{name}-2",
            Description="sim2real lambda-core test 2",
            TagSpecifications=[_tag_spec("security-group", f"{name}-2")],
        )["GroupId"]
        ctx.on_cleanup(lambda: _delete_in_use(lambda: ec2.delete_security_group(GroupId=sg_id2)))

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)
    role_arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    _poll_until(_attached, lambda ok: ok, timeout_s=30, interval_s=2)

    return {"subnet_id": subnet_id, "sg_id": sg_id, "sg_id2": sg_id2, "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
