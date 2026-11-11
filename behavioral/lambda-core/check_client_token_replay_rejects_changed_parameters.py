"""client-token-replay-rejects-changed-parameters."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-token-replay-rejects-changed-parameters"
GROUP = 'network-connectors'
SERVICES = ['lambda-core']

# A PENDING connector cannot be deleted (~250s of ResourceConflictException), so the one
# connector this check creates has to be retried out of PENDING in teardown.
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
_NOT_PROPAGATED = (
    "invalid ConnectorOperatorRole permissions",
    "unable to assume the provided NetworkConnectorOperatorRole",
)


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
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
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    zone = _usable_zones(ec2, 1)[0]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.95.1.0/24",
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
    """IAM propagation exposes no pollable condition; retry Create on the exact message to a
    deadline. A refused attempt can already hold its ClientToken, so each retry carries a fresh
    one; returns the response and the token that created the connector."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    base, attempt = kwargs["ClientToken"], 0
    while True:
        try:
            return lc.create_network_connector(**kwargs), kwargs["ClientToken"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message") or ""
            if not any(s in message for s in _NOT_PROPAGATED) or time.monotonic() > deadline:
                raise
            attempt += 1
            kwargs["ClientToken"] = f"{base}-{attempt}"
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
    """Retry the delete itself: DeleteNetworkConnector returns ResourceConflictException while the
    connector is PENDING (~250s after Create) or an update is InProgress (~257s after Update)."""
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
    """Replaying a ClientToken with identical parameters returns the same connector (only one
    exists), while reusing it with a different Name is refused with ResourceConflictException."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-behav-lc-tk-")
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
    token = ctx.unique_name("sim2real-lc-token-")

    first, token = _create_connector(
        lc, Name=label, Configuration=config, OperatorRole=operator, ClientToken=token
    )
    ctx.on_cleanup(lambda: _delete_connector(lc, first["Id"]))

    replay = lc.create_network_connector(
        Name=label, Configuration=config, OperatorRole=operator, ClientToken=token
    )
    assert replay["Id"] == first["Id"], (
        f"replaying ClientToken {token!r} minted a second connector {replay['Id']!r} "
        f"instead of returning {first['Id']!r}"
    )
    assert replay["Arn"] == first["Arn"], (
        f"the replay returned Arn {replay['Arn']!r}, expected {first['Arn']!r}"
    )

    named = [c for c in _list_connectors(lc) if c["Name"] == label]
    assert len(named) == 1, (
        f"two accepted creates under one ClientToken produced {len(named)} connectors named "
        f"{label!r} ({[c['Id'] for c in named]!r}); an idempotent replay must produce one"
    )

    changed = label + "-x"
    code, message = _error(
        lambda: lc.create_network_connector(
            Name=changed, Configuration=config, OperatorRole=operator, ClientToken=token
        )
    )
    assert code == "ResourceConflictException", (
        f"re-using ClientToken {token!r} with a different Name raised {code!r} ({message!r}), "
        "expected ResourceConflictException"
    )
    assert message == (
        "A request with the same client token but different parameters was already submitted"
    ), f"unexpected refusal message for a token/parameter mismatch: {message!r}"

    assert [c for c in _list_connectors(lc) if c["Name"] == changed] == [], (
        f"the refused token reuse created a connector named {changed!r} anyway"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
