"""duplicate-connector-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-connector-name-rejected"
GROUP = 'network-connectors'
SERVICES = ['lambda-core']

# A PENDING connector cannot be deleted (ResourceConflictException for minutes after Create), so
# both connectors this check makes have to be retried out in teardown.
_ACTIVE_WAIT_S = 600.0
_GONE_WAIT_S = 180.0
_TEARDOWN_WAIT_S = 900.0
_ROLE_PROPAGATION_WAIT_S = 120.0

_TRUST_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
# A role this fresh is rejected with either message, depending on how far IAM's own propagation
# has gotten — "unable to assume" moments after CreateRole, then "invalid
# ConnectorOperatorRole permissions" once the trust policy is visible but the attached policy
# is not yet. Both are the same not-yet-propagated condition and both are retried identically.
_NOT_PROPAGATED = ("invalid ConnectorOperatorRole permissions", "unable to assume the provided")


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a SUCCESS raises instead of
    returning a falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _usable_zones(ec2, want: int):
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(zones) >= want, f"region offers only {zones!r}, need {want} available zones"
    return zones[:want]


def _build_vpc(ctx, ec2, label: str):
    spec = [{"Key": "sim2real", "Value": label}]
    vpc = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    zone = _usable_zones(ec2, 1)[0]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.92.1.0/24",
        AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet))

    sg = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg))
    return subnet, sg


def _build_operator_role(ctx, iam, name: str) -> str:
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_LAMBDA),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    )
    return arn


def _create_connector(lc, **kwargs):
    """IAM propagation exposes no pollable condition; the bounded retry on the exact message,
    with a stated deadline, is what makes waiting for it correct."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message") or ""
            if not any(m in message for m in _NOT_PROPAGATED) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _list_connectors(lc, **kwargs):
    out, marker = [], None
    while True:
        page = lc.list_network_connectors(**kwargs, **({"Marker": marker} if marker else {}))
        out.extend(page["NetworkConnectors"])
        marker = page.get("NextMarker")
        if not marker:
            return out


def _delete_connector(lc, ident) -> None:
    """Retry DeleteNetworkConnector until accepted: it is refused ResourceConflictException while
    the connector is PENDING (minutes after Create) and again while an update is InProgress, so
    only retrying the delete itself is reliable."""
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            lc.delete_network_connector(Identifier=ident)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(10)
    gone = time.monotonic() + _GONE_WAIT_S
    while time.monotonic() < gone:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second connector with a taken name is ResourceConflictException with the exact "already
    exists in this account" message and the account still holds one connector by that name; the
    same payload under another name is accepted."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-behav-lc-dup-")
    subnet, sg = _build_vpc(ctx, ec2, label)
    operator = _build_operator_role(ctx, iam, label)
    config = {
        "VpcEgressConfiguration": {
            "SubnetIds": [subnet],
            "SecurityGroupIds": [sg],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }

    first = _create_connector(lc, Name=label, Configuration=config, OperatorRole=operator)
    ctx.on_cleanup(lambda: _delete_connector(lc, first["Id"]))
    assert first["Name"] == label, f"Create echoed Name {first['Name']!r}, expected {label!r}"

    code, message = _error(
        lambda: lc.create_network_connector(
            Name=label, Configuration=config, OperatorRole=operator
        )
    )
    assert code == "ResourceConflictException", (
        f"re-using the name {label!r} raised {code!r} ({message!r}), "
        "expected ResourceConflictException"
    )
    assert message == (
        f"A network connector with name '{label}' already exists in this account"
    ), f"unexpected collision message: {message!r}"

    same_name = [c for c in _list_connectors(lc) if c["Name"] == label]
    assert len(same_name) == 1, (
        f"after the refused create the account holds {len(same_name)} connectors named "
        f"{label!r} ({[c['Id'] for c in same_name]!r}); the collision must create nothing"
    )
    assert same_name[0]["Id"] == first["Id"], (
        f"the surviving connector is {same_name[0]['Id']!r}, not the original {first['Id']!r}"
    )

    other = label + "-b"
    control = _create_connector(lc, Name=other, Configuration=config, OperatorRole=operator)
    ctx.on_cleanup(lambda: _delete_connector(lc, control["Id"]))
    assert control["Id"] != first["Id"], (
        "positive control: the identical payload under a different name reused the id "
        f"{control['Id']!r} instead of minting a new one"
    )
    assert control["Name"] == other, (
        f"positive control: Create echoed Name {control['Name']!r}, expected {other!r}"
    )

    fetched = lc.get_network_connector(Identifier=control["Id"])
    assert fetched["Name"] == other, (
        f"positive control: independent read of {control['Id']!r} shows Name {fetched['Name']!r}, "
        f"expected {other!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
