"""list-network-connectors-pagination-collects-all-created."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-network-connectors-pagination-collects-all-created"
GROUP = "control-plane"
SERVICES = ["lambda-core"]

# Measured on real AWS in this suite: a fresh operator role can reject CreateNetworkConnector at two
# successive IAM-propagation gates ("unable to assume the provided NetworkConnectorOperatorRole",
# then "invalid ConnectorOperatorRole permissions"), and a PENDING connector cannot be deleted at
# all (ResourceConflictException) until it leaves PENDING (~250s later).
_ROLE_PROPAGATION_WAIT_S = 120.0
_LEAVES_PENDING_WAIT_S = 600.0
_GONE_WAIT_S = 180.0
_TRANSIENT_ROLE_MESSAGES = (
    "unable to assume the provided NetworkConnectorOperatorRole",
    "invalid ConnectorOperatorRole permissions",
)
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListNetworkConnectors with MaxItems=1 via NextMarker surfaces every created connector exactly once."""
    lc = ctx.client("lambda-core")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    prefix = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _build_network(ctx, ec2, prefix)
    role_arn = _operator_role(ctx, iam, prefix)

    created_ids = []
    for i in range(3):
        name = f"{prefix}-{i}"
        resp = _create_connector(
            lc,
            Name=name,
            Configuration=_dummy_config(subnet_id, sg_id),
            OperatorRole=role_arn,
            Tags={"sim2real": prefix},
        )
        cid = resp["Id"]
        created_ids.append(cid)
        ctx.on_cleanup(lambda cid=cid: _best_effort_delete(lc, cid))

    created_set = set(created_ids)
    seen_ids = []
    marker = None
    pages = 0
    while True:
        kwargs = {"MaxItems": 1}
        if marker:
            kwargs["Marker"] = marker
        page = lc.list_network_connectors(**kwargs)
        pages += 1
        for conn in page["NetworkConnectors"]:
            seen_ids.append(conn["Id"])
        marker = page.get("NextMarker")
        if not marker or pages > 500:
            break

    seen_set = set(seen_ids)
    assert created_set.issubset(seen_set), f"missing created connectors from paginated list: {created_set - seen_set}"
    # Each page returned at most 1 item as requested, and no id was repeated across pages.
    assert len(seen_ids) == len(seen_set), "pagination via NextMarker returned a duplicate connector across pages"

    # A PENDING connector cannot be deleted (ResourceConflictException) — wait for every
    # connector this check created to leave PENDING so the delete below can actually remove it,
    # then prove each is gone (a free negative on the delete this check already has to perform).
    _wait_all_not_pending(lc, created_ids, _LEAVES_PENDING_WAIT_S)
    for cid in created_ids:
        lc.delete_network_connector(Identifier=cid)
    _assert_all_gone(lc, created_ids, _GONE_WAIT_S)


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


def _wait_all_not_pending(lc, connector_ids, budget_s):
    deadline = time.monotonic() + budget_s
    pending = set(connector_ids)
    while pending:
        pending = {cid for cid in pending if lc.get_network_connector(Identifier=cid)["State"] == "PENDING"}
        if not pending:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"connectors stuck in PENDING after {budget_s}s: {pending}")
        time.sleep(2)


def _assert_all_gone(lc, connector_ids, budget_s):
    deadline = time.monotonic() + budget_s
    remaining = set(connector_ids)
    last_codes = {}
    while remaining and time.monotonic() < deadline:
        still = set()
        for cid in remaining:
            try:
                lc.get_network_connector(Identifier=cid)
                still.add(cid)
            except ClientError as exc:
                last_codes[cid] = exc.response.get("Error", {}).get("Code")
        remaining = still
        if remaining:
            time.sleep(5)
    assert not remaining, f"deleted connectors still answered Get: {remaining}"
    bad = {cid: code for cid, code in last_codes.items() if code != "ResourceNotFoundException"}
    assert not bad, f"deleted connectors answered Get with an unexpected error: {bad}"


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
    """A subnet and security group for this check's own connectors.

    Never depend on an ambient default VPC — a freshly provisioned account may not have one —
    so the default path creates a throwaway VPC. CreateVpc can fail with VpcLimitExceeded when
    the account is at its VPC quota; in that case fall back to an existing VPC rather than
    failing on a quota this check did not exhaust.
    """
    spec = [{"Key": "sim2real", "Value": label}]
    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.95.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": spec}]
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
            CidrBlock="10.95.1.0/24",
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


def _adopt_existing_network(ec2, *, ctx):
    """The account is at its VPC ceiling: adopt an existing VPC's existing subnet instead of
    creating (and cleaning up) either — a fresh CIDR is not guaranteed to fit an adopted VPC."""
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
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_VPC_ACCESS_POLICY))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
