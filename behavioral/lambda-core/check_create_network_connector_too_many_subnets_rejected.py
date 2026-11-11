"""create-network-connector-too-many-subnets-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-connector-too-many-subnets-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"
# Two distinct propagation-lag messages, measured on real AWS against a role whose trust policy
# and attached policy are both correct: the service's own ability to assume a just-created role
# lags separately from the attached-policy check it performs against EC2 afterward.
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_ROLE_PROPAGATION_WAIT_S = 120.0
# Measured on real AWS in this directory: a fresh connector stays PENDING for ~250s, and
# DeleteNetworkConnector is refused ResourceConflictException the whole time it is PENDING. Waiting
# it out here, in the body, is what lets the teardown below land inside the engine's own 60s cleanup
# budget instead of expiring against a connector that Delete cannot yet touch — a bare best-effort
# delete leaks it on every run.
_ACTIVE_WAIT_S = 600.0
_TEARDOWN_WAIT_S = 300.0
_GONE_WAIT_S = 180.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SubnetIds beyond the documented maximum of 16 is rejected, and no connector is created."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    role_arn = _operator_role(ctx)
    too_many_subnets = [f"subnet-{i:017x}" for i in range(17)]
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S

    code, message = _error(
        lambda: _create_connector(
            lc,
            deadline,
            Name=name,
            Configuration={
                "VpcEgressConfiguration": {
                    "SubnetIds": too_many_subnets,
                    "NetworkProtocol": "IPv4",
                    "AssociatedComputeResourceTypes": ["MicroVm"],
                }
            },
            OperatorRole=role_arn,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for 17 subnets, got {code!r} ({message!r})"
    )
    expected = (
        f"1 validation error detected: Value '[{', '.join(too_many_subnets)}]' at "
        "'configuration.vpcEgressConfiguration.subnetIds' failed to satisfy constraint: "
        "Member must have length less than or equal to 16"
    )
    assert message == expected, f"17 subnets rejected with message {message!r}, expected {expected!r}"

    matching = [c for c in _list_connectors(lc) if c["Name"] == name]
    assert not matching, "a rejected over-limit create must not have persisted a connector"

    # positive control: a request within the documented bound (using a real subnet/security-group) is accepted
    subnet_id, sg_id = _build_vpc(ctx)
    control = _create_connector(
        lc,
        deadline,
        Name=name,
        Configuration={
            "VpcEgressConfiguration": {
                "SubnetIds": [subnet_id],
                "SecurityGroupIds": [sg_id],
                "NetworkProtocol": "IPv4",
                "AssociatedComputeResourceTypes": ["MicroVm"],
            }
        },
        OperatorRole=role_arn,
    )
    ctx.on_cleanup(lambda: _delete_connector(lc, control["Id"]))
    assert control["Name"] == name

    # terminal assertion: an independent read at the destination, not the mutating call's own response
    fetched = lc.get_network_connector(Identifier=control["Id"])
    assert fetched["Id"] == control["Id"], (
        f"GetNetworkConnector({control['Id']!r}) returned Id {fetched.get('Id')!r}"
    )
    cfg = fetched["Configuration"]["VpcEgressConfiguration"]
    assert cfg["SubnetIds"] == [subnet_id], (
        f"positive control: GetNetworkConnector reported SubnetIds {cfg.get('SubnetIds')!r}, "
        f"expected [{subnet_id!r}]"
    )

    _wait_active(lc, control["Id"], _ACTIVE_WAIT_S)


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a SUCCESS raises instead of
    returning a falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _list_connectors(lc):
    """Every page of ListNetworkConnectors: the account is shared, so page one cannot answer
    an absence question."""
    out, marker = [], None
    while True:
        page = lc.list_network_connectors(MaxItems=100, **({"Marker": marker} if marker else {}))
        out.extend(page["NetworkConnectors"])
        marker = page.get("NextMarker")
        if not marker:
            return out


def _create_connector(lc, deadline, **kwargs):
    """IAM propagation exposes no pollable condition; the bounded retry on the exact message is
    what makes this correct."""
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


def _wait_active(lc, ident, budget_s):
    deadline = time.monotonic() + budget_s
    seen = None
    while time.monotonic() < deadline:
        seen = lc.get_network_connector(Identifier=ident)["State"]
        if seen == "ACTIVE":
            return
        assert seen == "PENDING", f"connector {ident!r} reached terminal state {seen!r} while waiting for ACTIVE"
        time.sleep(2)
    raise AssertionError(f"connector {ident!r} stuck in {seen!r} after {budget_s}s")


def _delete_connector(lc, ident) -> None:
    """Teardown that has to retry, because Delete is state-gated: DeleteNetworkConnector is refused
    ResourceConflictException while the connector is PENDING or while an update is InProgress. By
    the time this runs the body has already waited for ACTIVE, so this is defensive, not the
    primary mechanism — but a concurrent update racing in makes it possible, so we retry regardless."""
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


def _usable_zone(ec2):
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert zones, "region offers no available availability zones"
    return zones[0]


def _build_vpc(ctx):
    """A self-provisioned VPC/subnet/security-group — a freshly provisioned account may have no
    default VPC, so the positive control must not depend on one."""
    ec2 = ctx.client("ec2")
    label = ctx.unique_name("sim2real-lnc-")
    spec = [{"Key": "Name", "Value": label}]

    vpc_id = ec2.create_vpc(CidrBlock="10.94.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.94.1.0/24",
        AvailabilityZone=_usable_zone(ec2),
        TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _operator_role(ctx):
    """Create an IAM role with AWSLambdaNetworkConnectorOperatorPolicy attached, usable as OperatorRole."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lnc-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "Name", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not _attached():
        time.sleep(2)
    assert _attached(), f"AWSLambdaNetworkConnectorOperatorPolicy never attached to role {name!r}"
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
