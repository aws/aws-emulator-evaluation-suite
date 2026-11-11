"""create-rejected-with-unusable-operator-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rejected-with-unusable-operator-role"
GROUP = 'network-connectors'
SERVICES = ['lambda-core']

# The positive control creates a real connector, and a PENDING connector cannot be deleted
# (measured ~250s of ResourceConflictException), so teardown has to retry until it is accepted.
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
_TRUST_STATES = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_UNAUTHORIZED = (
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions"
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
        CidrBlock="10.94.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    zone = _usable_zones(ec2, 1)[0]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.94.1.0/24",
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


def _build_role(ctx, iam, name: str, trust: dict, policy_arn: str | None) -> str:
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if policy_arn:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return arn


def _create_connector(lc, **kwargs):
    """IAM propagation exposes no pollable condition; the bounded retry on the exact message,
    not a fixed pre-wait, is what makes this correct."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if _UNAUTHORIZED not in (err.get("Message") or "") or time.monotonic() > deadline:
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
    """Retry DeleteNetworkConnector until accepted, then wait for it to be gone.

    Delete is refused ResourceConflictException while PENDING (~250s after Create) and while an
    update is InProgress (~257s after Update), so only retrying the delete itself is reliable.
    """
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
    """CreateNetworkConnector refuses an operator role that does not trust lambda.amazonaws.com
    and one without EC2 permissions, each with its exact message and no connector left behind;
    a usable role is accepted and reaches ACTIVE.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-behav-lc-ur-")
    subnet, sg = _build_vpc(ctx, ec2, label)
    config = {
        "VpcEgressConfiguration": {
            "SubnetIds": [subnet],
            "SecurityGroupIds": [sg],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }

    untrusted = _build_role(ctx, iam, label + "-t", _TRUST_STATES, None)
    unprivileged = _build_role(ctx, iam, label + "-p", _TRUST_LAMBDA, None)
    good = _build_role(ctx, iam, label + "-g", _TRUST_LAMBDA, _VPC_ACCESS_POLICY)

    code, message = _error(
        lambda: lc.create_network_connector(
            Name=label, Configuration=config, OperatorRole=untrusted
        )
    )
    assert code == "InvalidParameterValueException", (
        f"a role that does not trust lambda.amazonaws.com raised {code!r} ({message!r}), "
        "expected InvalidParameterValueException"
    )
    assert message == _UNASSUMABLE, (
        f"unexpected refusal message for an unassumable operator role: {message!r}"
    )

    # The trust policy on `unprivileged` may still be propagating, in which case the service
    # reports the assume failure rather than the EC2 denial. Retry only while that is what we
    # see; the assertion below is on the exact permissions message, never on whichever arrives.
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        code, message = _error(
            lambda: lc.create_network_connector(
                Name=label, Configuration=config, OperatorRole=unprivileged
            )
        )
        if message != _UNASSUMABLE or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert code == "InvalidParameterValueException", (
        f"a role with no EC2 permissions raised {code!r} ({message!r}), "
        "expected InvalidParameterValueException"
    )
    assert message == _UNAUTHORIZED, (
        f"unexpected refusal message for an unprivileged operator role: {message!r}"
    )

    orphans = [c for c in _list_connectors(lc) if c["Name"] == label]
    assert orphans == [], (
        f"the two refused creates left {len(orphans)} connector(s) named {label!r} behind: "
        f"{[c['Id'] for c in orphans]!r}"
    )

    control = _create_connector(lc, Name=label, Configuration=config, OperatorRole=good)
    ctx.on_cleanup(lambda: _delete_connector(lc, control["Id"]))
    assert control["State"] == "PENDING", (
        "positive control: the same payload with a usable OperatorRole reported State "
        f"{control['State']!r}, expected 'PENDING'"
    )

    # An independent read may already see provisioning finished; _wait_active grades the end.
    pending = lc.get_network_connector(Identifier=control["Id"])
    assert pending["State"] in ("PENDING", "ACTIVE"), (
        "positive control: independent GetNetworkConnector reported State "
        f"{pending['State']!r}, expected 'PENDING' or 'ACTIVE'"
    )
    fetched = _wait_active(lc, control["Id"], _ACTIVE_WAIT_S)
    assert fetched["OperatorRole"] == good, (
        f"positive control: an independent Get reported OperatorRole {fetched.get('OperatorRole')!r}, "
        f"expected {good!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
