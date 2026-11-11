"""network-connector-arn-format-contains-account-and-region."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-arn-format-contains-account-and-region"
GROUP = "control-plane"
SERVICES = ["lambda-core"]

# Measured on real AWS in us-west-2: right after CreateRole, CreateNetworkConnector can reject
# the fresh role at TWO successive IAM-propagation gates -- "unable to assume the provided
# NetworkConnectorOperatorRole" (trust policy not yet visible) and, once that clears, "invalid
# ConnectorOperatorRole permissions" (the attached managed policy not yet visible). IAM exposes no
# condition that reports a role has become usable, so this is retried on the exact messages
# rather than waited out blind. A PENDING connector also cannot be deleted (ResourceConflictException)
# until it leaves PENDING.
_ROLE_PROPAGATION_WAIT_S = 120.0
_LEAVES_PENDING_WAIT_S = 600.0
_GONE_WAIT_S = 180.0
_TRANSIENT_ROLE_MESSAGES = (
    "unable to assume the provided NetworkConnectorOperatorRole",
    "invalid ConnectorOperatorRole permissions",
)

_TRUST_LAMBDA = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The Arn a network connector reports on an independent Get is a real lambda ARN scoped to
    the caller's account and region, and embeds the connector's own Id."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _build_network(ctx, ec2, name)
    role_arn = _operator_role(ctx, iam, name)

    created = _create_connector(
        lc,
        Name=name,
        Configuration=_dummy_config(subnet_id, sg_id),
        OperatorRole=role_arn,
        Tags={"sim2real": name},
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    fetched = lc.get_network_connector(Identifier=connector_id)
    arn = fetched["Arn"]
    assert arn == created["Arn"], f"Get Arn {arn!r} disagrees with Create Arn {created['Arn']!r}"
    parts = arn.split(":")
    assert parts[0] == "arn", arn
    assert parts[1] == "aws", f"expected the commercial partition, got {arn}"
    assert parts[2] == "lambda", f"expected lambda ARN namespace, got {arn}"
    assert parts[3] == ctx.region, f"ARN region {parts[3]!r} does not match target region {ctx.region!r}: {arn}"
    assert parts[4] == account_id, f"ARN account {parts[4]!r} does not match caller account {account_id!r}: {arn}"
    assert parts[5] == "network-connector", f"unexpected resource segment in ARN: {arn}"
    assert parts[6] == connector_id, (
        f"ARN resource id {parts[6]!r} does not match connector Id {connector_id!r}: {arn}"
    )

    # A PENDING connector cannot be deleted (ResourceConflictException). Wait for it to leave
    # PENDING so this check's own cleanup can actually remove what it created, then prove it gone
    # -- a free negative on the delete this check already has to perform.
    _wait_not_pending(lc, connector_id, _LEAVES_PENDING_WAIT_S)
    lc.delete_network_connector(Identifier=connector_id)
    deadline = time.monotonic() + _GONE_WAIT_S
    code = message = None
    while time.monotonic() < deadline:
        try:
            lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
            break
        time.sleep(5)
    assert code == "ResourceNotFoundException", (
        f"a deleted connector {connector_id!r} still answered Get (last error {code!r})"
    )
    assert message == f"Network connector not found: {arn}", f"Get on the deleted connector: message {message!r}"


def _dummy_config(subnet_id, sg_id):
    return {
        "VpcEgressConfiguration": {
            "SubnetIds": [subnet_id],
            "SecurityGroupIds": [sg_id],
            "NetworkProtocol": "IPv4",
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }


def _best_effort_delete(lc, connector_id):
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_not_pending(lc, connector_id, budget_s):
    deadline = time.monotonic() + budget_s
    state = "PENDING"
    while time.monotonic() < deadline:
        got = lc.get_network_connector(Identifier=connector_id)
        state = got["State"]
        if state != "PENDING":
            return got
        time.sleep(2)
    raise AssertionError(f"connector {connector_id!r} stuck in {state!r} after {budget_s}s")


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejections.

    IAM exposes no condition that reports a role has become usable, so the bounded retry on
    the exact propagation messages is what makes the call correct.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            if not any(m in message for m in _TRANSIENT_ROLE_MESSAGES) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _build_network(ctx, ec2, label: str):
    """A subnet and security group for this check's own connector.

    Never depend on an ambient default VPC -- a freshly provisioned account may not have one --
    so the default path creates a throwaway VPC. CreateVpc can fail with VpcLimitExceeded when
    the account is at its VPC quota; in that case fall back to an existing VPC rather than
    failing on a quota this check did not exhaust.
    """
    spec = [{"Key": "sim2real", "Value": label}]
    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.92.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}]
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

        zone = sorted(
            z["ZoneName"]
            for z in ec2.describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
            )["AvailabilityZones"]
        )[0]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.92.1.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": spec}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "VpcLimitExceeded":
            raise
        vpc_id, subnet_id = _adopt_existing_network(ec2, ctx=ctx)

    sg_id = ec2.create_security_group(
        GroupName=label,
        Description="sim2real lambda-core network connector egress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": spec}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _adopt_existing_network(ec2, *, ctx) -> tuple[str, str]:
    """The account is at its VPC ceiling: adopt an existing VPC's existing subnet instead of
    creating (and cleaning up) either -- a fresh CIDR is not guaranteed to fit an adopted VPC."""
    vpcs = sorted(ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"], key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        if subnets:
            return vpc["VpcId"], subnets[0]["SubnetId"]
    raise AssertionError("VpcLimitExceeded, but no existing VPC has a usable subnet to adopt")


def _operator_role(ctx, iam, name: str) -> str:
    """An operator role Lambda can assume with permissions to manage the connector's ENIs."""
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST_LAMBDA,
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
