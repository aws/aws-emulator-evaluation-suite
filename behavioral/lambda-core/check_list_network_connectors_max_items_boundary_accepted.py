"""list-network-connectors-max-items-boundary-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-network-connectors-max-items-boundary-accepted"
GROUP = "control-plane"
SERVICES = ["lambda-core"]

# Measured on real AWS: a freshly-attached OperatorRole is not immediately assumable by the
# lambda-core service, so CreateNetworkConnector rejects with one of these messages until IAM
# propagates the trust policy and the attached permissions policy. IAM exposes no condition that
# reports a role has become usable, so this is the one sanctioned wait: a bounded retry on the
# exact rejection text, never a blind sleep with nothing to fall back on if the account is slower
# than usual. Two distinct messages were observed on real AWS for the two propagation stages:
# "unable to assume the provided ... Role" (trust policy) and "invalid ConnectorOperatorRole
# permissions" (attached policy).
_ROLE_PROPAGATION_WAIT_S = 120.0
_NOT_PROPAGATED = ("unable to assume the provided", "invalid ConnectorOperatorRole permissions")

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaxItems=100 (the documented upper bound) is accepted and returns at most 100 connectors."""
    lc = ctx.client("lambda-core")
    name = ctx.unique_name("sim2real-lnc-")
    subnet_id, sg_id = _default_network(ctx)
    role_arn = _operator_role(ctx, name)
    created = _create_connector(
        lc, Name=name, Configuration=_dummy_config(subnet_id, sg_id), OperatorRole=role_arn
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    page = lc.list_network_connectors(MaxItems=100)
    assert len(page["NetworkConnectors"]) <= 100, (
        f"MaxItems=100 returned {len(page['NetworkConnectors'])} connectors, exceeding the requested page size"
    )
    ids = {c["Id"] for c in page["NetworkConnectors"]}
    assert connector_id in ids, "the created connector should be visible under the maximum allowed page size"
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


def _create_connector(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejection."""
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message") or ""
            if not any(s in message for s in _NOT_PROPAGATED) or time.monotonic() > deadline:
                raise
            time.sleep(2)


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
    """A subnet and the default security group of the account baseline's shared network."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "the account baseline's shared network is missing"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    # MicroVm connectors are not offered in every zone (us-west-2's usw2-az4 refuses them), so take
    # the first zone by name, as the suite's other connector checks do.
    subnet_id = min(subnets, key=lambda s: s["AvailabilityZone"])["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


def _operator_role(ctx, label):
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
        Tags=[{"Key": "sim2real", "Value": label}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
