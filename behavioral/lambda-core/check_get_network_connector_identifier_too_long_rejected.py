"""get-network-connector-identifier-too-long-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-network-connector-identifier-too-long-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda-core"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Identifier exceeding the 140-character length limit is a validation error, distinct from NotFound."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    subnet_ids, sg_id = _default_network(ctx)
    role_arn = _operator_role(ctx)
    created, _subnet_id = _create_in_supported_az(
        lc, subnet_ids, sg_id, Name=name, OperatorRole=role_arn, Tags={"sim2real": name}
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    # positive control: GetNetworkConnector works for a real identifier before we probe the rejection
    fetched = lc.get_network_connector(Identifier=connector_id)
    assert fetched["Id"] == connector_id, f"expected the positive-control read to return {connector_id!r}, got {fetched['Id']!r}"

    too_long_identifier = "a" * 141
    code, message = _error(lambda: lc.get_network_connector(Identifier=too_long_identifier))
    assert code == "ValidationException", (
        f"expected ValidationException for an over-long Identifier, got {code}"
    )
    assert message == (
        f"1 validation error detected: Value '{too_long_identifier}' at 'identifier' failed to satisfy "
        "constraint: Member must have length less than or equal to 140"
    ), f"over-long Identifier refusal message: got {message!r}"

    # terminal read: the real connector is still reachable through an independent GetNetworkConnector call
    fetched = lc.get_network_connector(Identifier=connector_id)
    assert fetched["Id"] == connector_id, f"expected the terminal read to still return {connector_id!r}, got {fetched['Id']!r}"

    # A PENDING connector refuses Delete, so the connector is deleted once its state allows it
    # and polled to not-found here rather than left to a best-effort cleanup.
    _delete_and_wait_gone(lc, connector_id)


_ROLE_PROPAGATION_WAIT_S = 120.0
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_UNAUTHORIZED = (
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions"
)


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
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a validation-class rejection, but the call SUCCEEDED and returned {result!r}")


def _create_connector(lc, **kwargs):
    """IAM propagation exposes no pollable condition; the bounded retry on the exact messages,
    with a deadline of _ROLE_PROPAGATION_WAIT_S, is what makes this correct. Measured on real
    AWS: a just-created role's trust policy (_UNASSUMABLE) and its attached EC2 permissions
    (_UNAUTHORIZED) can each still be propagating, and either can surface first."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            if message not in (_UNASSUMABLE, _UNAUTHORIZED) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _az_unsupported(exc) -> bool:
    """True for the refusal of a subnet whose AZ does not offer the MicroVm compute type."""
    message = exc.response.get("Error", {}).get("Message") or ""
    return message.startswith("Availability zone ") and message.endswith(
        " is not available for compute type MicroVm"
    )


def _create_in_supported_az(lc, subnet_ids, sg_id, **kwargs):
    """Not every AZ offers the MicroVm compute type, and CreateNetworkConnector refuses a subnet in
    one that does not; try the default VPC's subnets in turn and return (response, subnet_id) for
    the first one accepted. Any other refusal raises at once."""
    for i, subnet_id in enumerate(subnet_ids):
        try:
            return _create_connector(lc, Configuration=_dummy_config(subnet_id, sg_id), **kwargs), subnet_id
        except ClientError as exc:
            if not _az_unsupported(exc) or i == len(subnet_ids) - 1:
                raise
    raise AssertionError("the shared network has no subnets")


def _delete_and_wait_gone(lc, connector_id, timeout_s=600):
    """Delete, retrying the state-gated ResourceConflictException, then poll Get until 404."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lc.delete_network_connector(Identifier=connector_id)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2)
    while time.monotonic() < deadline:
        try:
            lc.get_network_connector(Identifier=connector_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"connector {connector_id!r} still answers Get after {timeout_s}s")


def _best_effort_delete(lc, connector_id):
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _default_network(ctx):
    """Adopt the run's shared network, falling back to any VPC, and its default security group
    (no resources created) — a freshly provisioned account may have no shared network."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    if not subnets:
        raise AssertionError(f"VPC {vpc_id} has no subnets")
    subnet_ids = [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZoneId"])]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError(f"VPC {vpc_id} has no default security group")
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"


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
        Tags=[{"Key": "sim2real", "Value": name}],
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
    if not _attached():
        raise AssertionError(f"{OPERATOR_POLICY_ARN} did not attach to role {name!r} within 30s")
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
