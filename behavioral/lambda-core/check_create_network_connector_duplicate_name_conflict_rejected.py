"""create-network-connector-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-connector-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda-core"]

# Measured on real AWS: right after CreateRole+AttachRolePolicy, CreateNetworkConnector can still
# reject with the exact message below while STS trust-policy assumption propagates, even though the
# attached policy is already visible via ListAttachedRolePolicies. Retrying the create call itself
# on that exact message is the only correct barrier.
_ROLE_PROPAGATION_WAIT_S = 120.0
_UNASSUMABLE_TRANSIENT = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
# The attached operator policy's EC2 permissions propagate the same way.
_UNAUTHORIZED_TRANSIENT = (
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second connector with a Name already in use is rejected, and the original is untouched."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    subnet_ids, sg_id = _default_network(ctx)
    role_arn = _operator_role(ctx)
    first, subnet_id = _create_in_supported_az(lc, subnet_ids, sg_id, Name=name, OperatorRole=role_arn)
    connector_id = first["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    code, message = _error(
        lambda: lc.create_network_connector(
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
    )
    assert code == "ResourceConflictException", f"expected ResourceConflictException for a duplicate Name, got {code}"
    assert message == f"A network connector with name '{name}' already exists in this account", (
        f"duplicate-Name refusal message: got {message!r}"
    )

    # effect absent: the original connector's configuration must be unchanged by the rejected attempt
    unchanged = lc.get_network_connector(Identifier=connector_id)
    assert unchanged["Configuration"]["VpcEgressConfiguration"]["SubnetIds"] == [subnet_id]

    listing = lc.list_network_connectors(MaxItems=100)
    matching = [c for c in listing["NetworkConnectors"] if c["Name"] == name]
    assert len(matching) == 1, f"the rejected duplicate-name create must not have persisted a second connector: {matching}"

    # positive control: a distinct name succeeds normally
    other_name = ctx.unique_name("sim2real-lnc-ctrl-")
    control = _create_connector(lc, Name=other_name, Configuration=_dummy_config(subnet_id, sg_id), OperatorRole=role_arn)
    ctx.on_cleanup(lambda: _best_effort_delete(lc, control["Id"]))
    assert control["Name"] == other_name

    # A PENDING connector refuses Delete, so both connectors are deleted once their state allows
    # it and polled to not-found here rather than left to a best-effort cleanup.
    _delete_and_wait_gone(lc, control["Id"])
    _delete_and_wait_gone(lc, connector_id)


# ===== helpers =====

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
    """The (Code, Message) of the ClientError fn() raises; a SUCCESS raises, because real AWS
    refuses this call."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the duplicate-name create to be refused, but it SUCCEEDED and returned {result!r}")


def _create_connector(lc, **kwargs):
    """Bounded retry on the exact transient role-propagation messages (see the module-level
    comment); any other error, or the same error past the deadline, raises."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Message") in (_UNASSUMABLE_TRANSIENT, _UNAUTHORIZED_TRANSIENT)
            if not transient or time.monotonic() > deadline:
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
    """Look up the run's shared network's subnets and default security group (no resources created)."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZoneId"])]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
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
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
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
        raise AssertionError(f"AttachRolePolicy for {OPERATOR_POLICY_ARN} on {name!r} never became visible")
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
