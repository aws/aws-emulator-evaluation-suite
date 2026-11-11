"""get-network-connector-by-name-id-and-arn-equivalent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-network-connector-by-name-id-and-arn-equivalent"
GROUP = "control-plane"
SERVICES = ["lambda-core"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNetworkConnector accepts the connector's Id, Name, or Arn as Identifier and returns the same resource."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    subnet_ids, sg_id = _default_network(ctx)
    role_arn = _operator_role(ctx)
    created = _create_connector(
        lc,
        subnet_ids,
        sg_id,
        Name=name,
        OperatorRole=role_arn,
        Tags={"sim2real": name},
    )
    connector_id = created["Id"]
    connector_arn = created["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    by_id = lc.get_network_connector(Identifier=connector_id)
    by_name = lc.get_network_connector(Identifier=name)
    by_arn = lc.get_network_connector(Identifier=connector_arn)

    for label, resp in (("id", by_id), ("name", by_name), ("arn", by_arn)):
        assert resp["Id"] == connector_id, f"lookup by {label} returned a different Id"
        assert resp["Arn"] == connector_arn, f"lookup by {label} returned a different Arn"
        assert resp["Name"] == name, f"lookup by {label} returned a different Name"

    _wait_not_pending(ctx, lc, connector_id)


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


def _wait_not_pending(ctx, lc, connector_id):
    """DeleteNetworkConnector is refused ResourceConflictException while the connector is PENDING
    (~250 s after Create), longer than the cleanup budget, so the body waits it out."""
    left = ctx.time_left()
    budget_s = 600.0 if left is None else max(1.0, min(600.0, left - 5.0))
    deadline = time.monotonic() + budget_s
    state = "PENDING"
    while time.monotonic() < deadline:
        state = lc.get_network_connector(Identifier=connector_id)["State"]
        if state != "PENDING":
            return
        time.sleep(2)
    raise AssertionError(f"connector {connector_id!r} stuck in {state!r} after {budget_s:.0f}s")


def _best_effort_delete(lc, connector_id):
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _default_network(ctx):
    """Look up the run's shared network's subnets (one per AZ) and default security group (no
    resources created). Every AZ is returned, not just the first, because not every AZ in a
    region supports the MicroVm compute type and CreateNetworkConnector says so per-subnet."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_ids, sg_id


OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"

# The service reports a not-yet-propagated OperatorRole with one of these two exact messages —
# either the trust policy or the EC2 permissions can still be propagating independently — never with
# anything else for a role that trusts lambda.amazonaws.com and carries the operator policy.
# Retrying CreateNetworkConnector on these specific messages is the bounded, evidence-based wait; a
# blind sleep is not.
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_UNAUTHORIZED = (
    "Encountered unauthorized operation while calling EC2 due to invalid "
    "ConnectorOperatorRole permissions"
)
_PROPAGATION_MESSAGES = (_UNASSUMABLE, _UNAUTHORIZED)
_ROLE_PROPAGATION_WAIT_S = 120.0

# Measured on real AWS: not every AZ in the region supports the MicroVm compute type, and
# CreateNetworkConnector rejects a subnet in an unsupported AZ with this substring rather than
# with a code distinct from a bad-role rejection. Falling back to the next default-VPC subnet on
# this exact message is the fix; it is not a role-propagation retry.
_AZ_UNAVAILABLE_FOR_COMPUTE_TYPE = "is not available for compute type"


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
        RoleName=name, AssumeRolePolicyDocument=trust_policy, Tags=[{"Key": "sim2real", "Value": name}]
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
    return role_arn


def _create_connector(lc, subnet_ids, sg_id, **kwargs):
    """IAM propagation exposes no pollable condition; retry CreateNetworkConnector on the exact
    unready-role message real AWS reports while it lags, rather than sleeping blindly first.
    Separately, fall back across the default VPC's other AZs on the compute-type-unavailable
    message — that is an AZ problem, not a role problem, and needs no wait at all."""
    candidates = list(subnet_ids)
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(
                Configuration=_dummy_config(candidates[0], sg_id), **kwargs
            )
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message") or ""
            if _AZ_UNAVAILABLE_FOR_COMPUTE_TYPE in message and len(candidates) > 1:
                candidates.pop(0)
                continue
            if message not in _PROPAGATION_MESSAGES or time.monotonic() > deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
