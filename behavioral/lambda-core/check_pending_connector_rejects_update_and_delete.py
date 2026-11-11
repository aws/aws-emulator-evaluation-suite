"""pending-connector-rejects-update-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pending-connector-rejects-update-and-delete"
GROUP = 'network-connectors'
SERVICES = ['lambda-core']

# A connector sits in PENDING for ~250s after Create and both mutations are refused for that
# whole window, so the positive control (the same Delete once ACTIVE) must wait it out.
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
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
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
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    subnets = []
    for i, zone in enumerate(_usable_zones(ec2, 2)):
        sid = ec2.create_subnet(
            VpcId=vpc,
            CidrBlock=f"10.91.{i + 1}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sid: ec2.delete_subnet(SubnetId=s))
        subnets.append(sid)

    sg = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg))
    return subnets, sg


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
    """IAM exposes no condition that says a role has become usable, so this retries on the
    exact propagation messages with a deadline — never an unconditional wait."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message") or ""
            transient = message == _UNASSUMABLE or _NOT_PROPAGATED in message
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(2)


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
            time.sleep(2)
    gone = time.monotonic() + _GONE_WAIT_S
    while time.monotonic() < gone:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A PENDING connector refuses Update and Delete with ResourceConflictException and its exact
    messages, leaving its configuration untouched; the same Delete is accepted once ACTIVE.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-behav-lc-pd-")
    subnets, sg = _build_vpc(ctx, ec2, label)
    operator = _build_operator_role(ctx, iam, label)

    def _egress(subnet_ids):
        return {
            "VpcEgressConfiguration": {
                "SubnetIds": subnet_ids,
                "SecurityGroupIds": [sg],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        }

    # PENDING only moves forward, so a Get that still reports PENDING after a mutation proves the
    # mutation hit a PENDING connector. A connector that left PENDING before both refusals were
    # proven is replaced by a fresh one.
    created = ident = None
    proven = False
    for attempt in range(5):
        created = _create_connector(
            lc, Name=label if not attempt else f"{label}-{attempt}",
            Configuration=_egress([subnets[0]]), OperatorRole=operator,
        )
        ident = created["Id"]
        ctx.on_cleanup(lambda i=ident: _delete_connector(lc, i))
        assert created["State"] == "PENDING", (
            f"a fresh connector reported State {created['State']!r}, expected 'PENDING'"
        )

        try:
            lc.update_network_connector(Identifier=ident, Configuration=_egress(subnets))
        except ClientError as exc:
            err = exc.response.get("Error", {})
            refused = (err.get("Code"), err.get("Message") or "")
        else:
            refused = None
        after_update = lc.get_network_connector(Identifier=ident)["State"]
        if refused is None:
            assert after_update != "PENDING", (
                "updating a PENDING connector was accepted, expected ResourceConflictException"
            )
            continue
        code, message = refused
        assert code == "ResourceConflictException", (
            f"updating a PENDING connector raised {code!r} ({message!r}), "
            "expected ResourceConflictException"
        )
        assert message == (
            f"Network connector {ident} is in state Pending and cannot be updated. "
            "Only ACTIVE connectors can be updated."
        ), f"unexpected refusal message for a PENDING update: {message!r}"
        if after_update != "PENDING":
            continue

        try:
            lc.delete_network_connector(Identifier=ident)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            refused = (err.get("Code"), err.get("Message") or "")
        else:
            refused = None
        if refused is None:
            continue
        code, message = refused
        assert code == "ResourceConflictException", (
            f"deleting a PENDING connector raised {code!r} ({message!r}), "
            "expected ResourceConflictException"
        )
        assert message == "Network connector is in PENDING state and cannot be deleted", (
            f"unexpected refusal message for a PENDING delete: {message!r}"
        )

        still = lc.get_network_connector(Identifier=ident)
        assert still["Configuration"]["VpcEgressConfiguration"]["SubnetIds"] == [subnets[0]], (
            "the refused update was applied anyway: stored subnets are "
            f"{still['Configuration']['VpcEgressConfiguration']['SubnetIds']!r}, "
            f"expected only {subnets[0]!r}"
        )
        assert still["State"] in ("PENDING", "ACTIVE"), (
            f"the refused delete moved the connector to {still['State']!r}, expected 'PENDING' "
            "or 'ACTIVE'"
        )
        proven = True
        break
    assert proven, (
        "no connector stayed PENDING through both the Update and the Delete, so neither refusal "
        "could be observed against a PENDING connector"
    )

    deadline = time.monotonic() + _budget_s(ctx, _ACTIVE_WAIT_S)
    state = "PENDING"
    while True:
        got = lc.get_network_connector(Identifier=ident)
        state = got["State"]
        if state != "PENDING" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    if state == "PENDING" and _budget_spent(ctx):
        raise TimeoutError("connector to leave PENDING: the run budget ended first; not graded")
    assert state == "ACTIVE", (
        f"connector never became ACTIVE (last state {state!r}) — the positive control below "
        "cannot distinguish a state gate from a broken request without it"
    )

    accepted = lc.delete_network_connector(Identifier=ident)
    assert accepted["Id"] == ident, f"the accepted Delete echoed Id {accepted['Id']!r}, expected {ident!r}"
    assert accepted["State"] == "DELETING", (
        "positive control: the SAME Delete that was refused while PENDING reported "
        f"State {accepted['State']!r} once ACTIVE, expected 'DELETING'"
    )

    gone = time.monotonic() + _budget_s(ctx, _GONE_WAIT_S)
    code = message = None
    while True:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            break
        if time.monotonic() >= gone:
            break
        time.sleep(2)
    if code is None and _budget_spent(ctx):
        raise TimeoutError("deleted connector to disappear: the run budget ended first; not graded")
    assert code == "ResourceNotFoundException", (
        f"the accepted delete never made the connector disappear (last error {code!r})"
    )
    # Get by Id names the connector by its full ARN.
    assert message == f"Network connector not found: {created['Arn']}", (
        f"Get of the deleted connector said {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
