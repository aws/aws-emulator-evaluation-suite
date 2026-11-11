"""create-rejected-without-operator-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rejected-without-operator-role"
GROUP = 'network-connectors'
SERVICES = ['lambda-core']

# The positive control creates a real connector, and a PENDING connector cannot be deleted
# (ResourceConflictException for minutes), so teardown has to retry until it is accepted.
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
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_NOT_YET_ASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)


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
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    zone = _usable_zones(ec2, 1)[0]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.93.1.0/24",
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
    """IAM propagation exposes no pollable condition; the bounded retry on the exact message is
    what makes this correct. The role is validated in two sequential asynchronous stages — the
    service first has to be ABLE TO ASSUME the role (trust policy propagation), then it has to be
    ALLOWED to drive EC2 with it (permissions propagation) — so both transient messages, not just
    the second, must be retried."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            transient = _NOT_PROPAGATED in message or message == _NOT_YET_ASSUMABLE
            if not transient or time.monotonic() > deadline:
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


def _wait_active(lc, ident, budget_s):
    """Bounded poll to the terminal ACTIVE state; any other non-PENDING state fails loudly."""
    deadline = time.monotonic() + budget_s
    seen = None
    while time.monotonic() < deadline:
        got = lc.get_network_connector(Identifier=ident)
        seen = got["State"]
        if seen == "ACTIVE":
            return got
        assert seen == "PENDING", (
            f"connector {ident!r} reached state {seen!r} "
            f"(reason {got.get('StateReason')!r}) while waiting for ACTIVE"
        )
        time.sleep(2)
    raise AssertionError(f"connector {ident!r} stuck in {seen!r} after {budget_s}s")


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
    """A VPC_EGRESS connector without OperatorRole (optional in the model) is refused with the
    exact InvalidParameterValueException message and creates nothing; the same request with the
    role is accepted PENDING and returns that role."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-behav-lc-nr-")
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

    code, message = _error(
        lambda: lc.create_network_connector(Name=label, Configuration=config)
    )
    assert code == "InvalidParameterValueException", (
        f"CreateNetworkConnector without OperatorRole raised {code!r} ({message!r}), "
        "expected InvalidParameterValueException"
    )
    assert message == (
        "NetworkConnectorOperatorRole is required for VPC_EGRESS connector type"
    ), f"unexpected refusal message for a missing OperatorRole: {message!r}"

    orphans = [c for c in _list_connectors(lc) if c["Name"] == label]
    assert orphans == [], (
        f"the refused create left {len(orphans)} connector(s) named {label!r} behind: "
        f"{[c['Id'] for c in orphans]!r}"
    )

    control = _create_connector(
        lc, Name=label, Configuration=config, OperatorRole=operator
    )
    ctx.on_cleanup(lambda: _delete_connector(lc, control["Id"]))
    assert control["State"] == "PENDING", (
        "positive control: the same payload with a usable OperatorRole reported State "
        f"{control['State']!r}, expected 'PENDING'"
    )
    assert control["OperatorRole"] == operator, (
        f"positive control: Create echoed OperatorRole {control.get('OperatorRole')!r}, "
        f"expected {operator!r}"
    )

    # An independent read may already see provisioning finished; _wait_active grades the end.
    pending = lc.get_network_connector(Identifier=control["Id"])
    assert pending["State"] in ("PENDING", "ACTIVE"), (
        "positive control: independent GetNetworkConnector reported State "
        f"{pending['State']!r}, expected 'PENDING' or 'ACTIVE'"
    )
    fetched = _wait_active(lc, control["Id"], _ACTIVE_WAIT_S)
    assert fetched["OperatorRole"] == operator, (
        "positive control: independent GetNetworkConnector reported OperatorRole "
        f"{fetched.get('OperatorRole')!r}, expected {operator!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
