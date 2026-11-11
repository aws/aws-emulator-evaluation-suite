"""create-network-connector-operator-role-required-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-connector-operator-role-required-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
# Real AWS returns either message depending on which piece of IAM state (the trust policy or the
# attached permissions) it observes as not-yet-propagated for a just-created role.
_NOT_PROPAGATED = (
    "unable to assume the provided NetworkConnectorOperatorRole",
    "invalid ConnectorOperatorRole permissions",
)
_ROLE_PROPAGATION_WAIT_S = 120.0
_GONE_WAIT_S = 180.0
_TEARDOWN_WAIT_S = 300.0

_TRUST_LAMBDA = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkConnector without an OperatorRole is rejected with the exact message and persists
    nothing, although the model marks OperatorRole optional; the same request with one succeeds."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _build_network(ctx, ec2, label)
    config = _dummy_config(subnet_id, sg_id)

    code, message = _error(lambda: lc.create_network_connector(Name=label, Configuration=config))
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException when OperatorRole is omitted, got {code!r} ({message!r})"
    )
    assert message == (
        "NetworkConnectorOperatorRole is required for VPC_EGRESS connector type"
    ), f"unexpected refusal message for a missing OperatorRole: {message!r}"

    listing = lc.list_network_connectors(MaxItems=100)
    matching = [c for c in listing["NetworkConnectors"] if c["Name"] == label]
    assert not matching, "a rejected create missing OperatorRole must not have persisted a connector"

    # positive control: the identical request WITH an OperatorRole succeeds
    role_arn = _operator_role(ctx, iam, label)
    created = _create_connector(lc, Name=label, Configuration=config, OperatorRole=role_arn)
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_connector(lc, connector_id))
    assert created["OperatorRole"] == role_arn, (
        f"positive control: Create echoed OperatorRole {created.get('OperatorRole')!r}, expected {role_arn!r}"
    )

    fetched = lc.get_network_connector(Identifier=connector_id)
    assert fetched["OperatorRole"] == role_arn, (
        f"positive control: Get echoed OperatorRole {fetched.get('OperatorRole')!r}, expected {role_arn!r}"
    )

    # Delete in-body (not just at teardown) and confirm gone before the VPC/subnet/security-group
    # cleanup that follows: DeleteNetworkConnector accepting the request does not mean an immediate
    # Get 404s — measured on real AWS, Get kept answering 200 for a few seconds after Delete was
    # accepted — and tearing down the VPC before that catches up leaves a DependencyViolation-
    # blocked VPC behind. Poll for the 404 instead of checking once.
    _delete_connector(lc, connector_id)
    _wait_gone(lc, connector_id)


def _dummy_config(subnet_id, sg_id):
    return {
        "VpcEgressConfiguration": {
            "SubnetIds": [subnet_id],
            "SecurityGroupIds": [sg_id],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }


def _error(fn):
    """(Error.Code, Error.Message); a SUCCESS raises instead of returning a falsy sentinel that
    would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _build_network(ctx, ec2, label):
    """Create a fresh VPC/subnet/security group; never depend on the account having a default VPC."""
    def _tags(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "sim2real", "Value": label}]}]

    window: dict = {}

    vpc_id = ec2.create_vpc(CidrBlock="10.94.0.0/16", TagSpecifications=_tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_ec2(window, ec2.delete_vpc, VpcId=vpc_id))

    zone = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )[
            "AvailabilityZones"
        ]
    )[0]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.94.1.0/24", AvailabilityZone=zone, TagSpecifications=_tags("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_ec2(window, ec2.delete_subnet, SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc_id,
        TagSpecifications=_tags("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_ec2(window, ec2.delete_security_group, GroupId=sg_id))
    return subnet_id, sg_id


_EC2_NOT_FOUND = {"InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound"}
_EC2_TEARDOWN_S = 300.0


def _delete_ec2(window: dict, fn, **kwargs) -> None:
    """Delete, returning on not-found and retrying DependencyViolation (the connector's ENIs still
    leaving) every 2 s inside one window shared by the network's deletes; anything else raises."""
    deadline = window.setdefault("deadline", time.monotonic() + _EC2_TEARDOWN_S)
    while True:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _EC2_NOT_FOUND:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _operator_role(ctx, iam, label):
    """Create an IAM role usable as OperatorRole, tagged with the check's label."""
    name = ctx.unique_name("sim2real-lnc-role-")
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST_LAMBDA, Tags=[{"Key": "sim2real", "Value": label}]
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))
    return role_arn


def _create_connector(lc, **kwargs):
    """IAM role propagation exposes no pollable condition; retry Create on the exact propagation
    error instead of guessing a wait duration."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = err.get("Message") or ""
            if not any(frag in msg for frag in _NOT_PROPAGATED) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_connector(lc, connector_id):
    """DeleteNetworkConnector is refused with ResourceConflictException while the connector is not
    yet stable; retry the delete itself rather than polling state, and swallow only not-found."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            lc.delete_network_connector(Identifier=connector_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _wait_gone(lc, connector_id):
    """Get keeps answering 200 for a few seconds after Delete is accepted; poll for the 404 rather
    than trusting Delete's own acceptance as proof, and raise (never silently give up) on timeout.
    A successful Get here means "not yet gone" (retry it), not the unexpected-success case _error
    exists for -- reusing that helper on this call would misread every still-visible poll as a
    hard failure instead of the expected transient state."""
    deadline = time.monotonic() + _GONE_WAIT_S
    while True:
        try:
            lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(
                f"connector {connector_id!r} was still visible via Get {_GONE_WAIT_S}s after "
                "Delete was accepted, expected ResourceNotFoundException"
            )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
