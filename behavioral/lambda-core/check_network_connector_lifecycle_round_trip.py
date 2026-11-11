"""network-connector-lifecycle-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-lifecycle-round-trip"
GROUP = 'network-connectors'
SERVICES = ['lambda-core']

# A PENDING connector CANNOT be deleted at all (ResourceConflictException), so every wait
# below is on the critical path, not padding.
POLL_BUDGET_S = 900.0
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
# Until a new role's trust policy propagates, CreateNetworkConnector rejects with this message
# (not the EC2-permissions one, which is for an assumable role lacking VPC access).
_NOT_PROPAGATED = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)


def _error(fn):
    """Return the ClientError response fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _assert_not_found(resp, what, subject=None, *, expected_message):
    """ResourceNotFoundException + HTTP 404 + the exact message (naming the subject if given)."""
    err = resp.get("Error", {})
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == "ResourceNotFoundException", f"{what}: expected ResourceNotFoundException, got {err.get('Code')!r}"
    assert status == 404, f"{what}: expected HTTP 404, got {status!r}"
    assert err.get("Message") == expected_message, f'expected the message {expected_message!r}, got {err.get("Message")!r}'
    if subject is not None:
        assert subject in err["Message"], f"{what}: expected the message to name {subject!r}, got {err['Message']!r}"


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
    """A VPC with two subnets in distinct AZs and one security group."""
    spec = [{"Key": "sim2real", "Value": label}]
    vpc = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc))

    zones = _usable_zones(ec2, 2)
    subnets = []
    for i, zone in enumerate(zones):
        sid = ec2.create_subnet(
            VpcId=vpc,
            CidrBlock=f"10.90.{i + 1}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s))
        subnets.append(sid)

    sg = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg))
    return subnets, sg


def _build_operator_role(ctx, iam, name: str) -> str:
    """An operator role the service can assume AND that can drive EC2 — both are validated
    synchronously by CreateNetworkConnector."""
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
    """CreateNetworkConnector, retrying only the IAM-propagation rejection; IAM exposes no
    condition that reports a role has become usable."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if _NOT_PROPAGATED not in (err.get("Message") or "") or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _list_connectors(lc, **kwargs):
    """Every page of ListNetworkConnectors; page one alone cannot answer membership."""
    out, marker = [], None
    while True:
        page = lc.list_network_connectors(**kwargs, **({"Marker": marker} if marker else {}))
        out.extend(page["NetworkConnectors"])
        marker = page.get("NextMarker")
        if not marker:
            return out


def _wait_state(lc, ident, wanted, budget_s):
    deadline = time.monotonic() + budget_s
    seen = None
    while time.monotonic() < deadline:
        got = lc.get_network_connector(Identifier=ident)
        seen = got["State"]
        if seen == wanted:
            return got
        assert seen in ("PENDING", wanted), (
            f"connector {ident!r} reached terminal state {seen!r} "
            f"(reason {got.get('StateReason')!r} / {got.get('StateReasonCode')!r}) "
            f"while waiting for {wanted!r}"
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
    gone = time.monotonic() + POLL_BUDGET_S
    while time.monotonic() < gone:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A connector goes created -> ACTIVE -> updated -> gone: id, name and ARN resolve alike, List's
    State filter tracks it, the update settles Successful and is served, and after delete every
    read and update path returns the exact 404.
    """
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    label = ctx.unique_name("sim2real-behav-lc-rt-")
    subnets, sg = _build_vpc(ctx, ec2, label)
    operator = _build_operator_role(ctx, iam, label)

    created = _create_connector(
        lc,
        Name=label,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": [subnets[0]],
                "SecurityGroupIds": [sg],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
        OperatorRole=operator,
    )
    ident = created["Id"]
    ctx.on_cleanup(lambda: _delete_connector(lc, ident))

    assert created["Name"] == label, f"Create echoed Name {created['Name']!r}, expected {label!r}"
    parts = created["Arn"].split(":")
    assert parts[2] == "lambda" and parts[3] == ctx.region, (
        f"connector ARN {created['Arn']!r} is not a lambda ARN in {ctx.region!r}"
    )
    assert parts[4] == ctx.account, f"connector ARN {created['Arn']!r} does not carry the caller account"
    assert parts[5] == "network-connector" and parts[6] == ident, (
        f"connector ARN {created['Arn']!r} does not end in network-connector:{ident}"
    )

    ready = _wait_state(lc, ident, "ACTIVE", POLL_BUDGET_S)
    assert ready["Configuration"]["VpcEgressConfiguration"]["SubnetIds"] == [subnets[0]], (
        "provisioning rewrote the requested subnets: "
        f"{ready['Configuration']['VpcEgressConfiguration']['SubnetIds']!r}"
    )

    by_name = lc.get_network_connector(Identifier=label)
    by_arn = lc.get_network_connector(Identifier=created["Arn"])
    for form, got in (("name", by_name), ("ARN", by_arn)):
        assert got["Id"] == ident and got["Arn"] == created["Arn"], (
            f"Get by {form} resolved to {got['Id']!r}/{got['Arn']!r}, not {ident!r}/{created['Arn']!r}"
        )

    active_now = {c["Id"]: c for c in _list_connectors(lc, State="ACTIVE")}
    assert ident in active_now, f"an ACTIVE connector {ident!r} is missing from List State=ACTIVE"
    assert active_now[ident]["Type"] == "VPC_EGRESS", (
        f"List reported Type {active_now[ident]['Type']!r}, expected 'VPC_EGRESS'"
    )
    assert ident not in {c["Id"] for c in _list_connectors(lc, State="PENDING")}, (
        f"connector {ident!r} is still listed as PENDING after reaching ACTIVE"
    )

    updated = lc.update_network_connector(
        Identifier=ident,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": subnets,
                "SecurityGroupIds": [sg],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
    )
    assert set(updated["Configuration"]["VpcEgressConfiguration"]["SubnetIds"]) == set(subnets), (
        "the accepted update did not echo the requested subnet set: "
        f"{updated['Configuration']['VpcEgressConfiguration']['SubnetIds']!r}"
    )

    deadline = time.monotonic() + POLL_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = lc.get_network_connector(Identifier=ident)["LastUpdateStatus"]
        if status != "InProgress":
            break
        time.sleep(2)
    assert status == "Successful", f"update settled as {status!r}, expected 'Successful'"

    settled = lc.get_network_connector(Identifier=ident)
    assert set(settled["Configuration"]["VpcEgressConfiguration"]["SubnetIds"]) == set(subnets), (
        "once the update settled Successful, Get still served "
        f"{settled['Configuration']['VpcEgressConfiguration']['SubnetIds']!r}, "
        f"expected {sorted(subnets)!r}"
    )

    lc.delete_network_connector(Identifier=ident)

    # Gone beat 1: Get by id converges to ResourceNotFoundException (404) naming the connector,
    # and the name and ARN forms resolve to nothing either.
    gone = time.monotonic() + POLL_BUDGET_S
    while True:
        try:
            lc.get_network_connector(Identifier=ident)
        except ClientError as exc:
            _assert_not_found(exc.response, "Get by id after delete", ident, expected_message=f"Network connector not found: {got['Arn']}")
            break
        if time.monotonic() > gone:
            raise AssertionError(f"a deleted connector still answered Get after {POLL_BUDGET_S:.0f}s")
        time.sleep(5)
    for form in (label, created["Arn"]):
        _assert_not_found(_error(lambda f=form: lc.get_network_connector(Identifier=f)), f"Get by {form!r} after delete", expected_message=f"Network connector not found: {form}")
    # Gone beat 2: no listing (the API has no Name filter, so the full list) enumerates it.
    assert ident not in {c["Id"] for c in _list_connectors(lc)}, (
        f"a deleted connector {ident!r} is still enumerated by ListNetworkConnectors"
    )
    # Gone beat 3: an update on the dead connector is refused.
    _assert_not_found(
        _error(
            lambda: lc.update_network_connector(
                Identifier=ident,
                Configuration={
                    "VpcEgressConfiguration": {
                        "SubnetIds": [subnets[0]],
                        "SecurityGroupIds": [sg],
                        "NetworkProtocol": "IPv4",
                        "AssociatedComputeResourceTypes": ["MicroVm"],
                    }
                },
            )
        ),
        "UpdateNetworkConnector on the deleted connector",
        expected_message=f"Network connector not found: {ident}",
    )

# The connector's hyperplane ENIs outlive DeleteNetworkConnector, so network teardown waits
# (bounded) for them to leave and retries DependencyViolation, then names the ENIs left.
_NET_TEARDOWN_S = _TEARDOWN_WAIT_S
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
