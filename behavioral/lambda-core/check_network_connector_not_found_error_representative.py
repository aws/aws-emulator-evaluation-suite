"""network-connector-not-found-error-representative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-not-found-error-representative"
GROUP = "overly-permissive"
SERVICES = ["lambda-core"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Get/Update/Delete on a syntactically valid but non-existent connector all fail with ResourceNotFoundException."""
    lc = ctx.client("lambda-core")
    bogus_id = ctx.unique_name("sim2real-nonexistent-")
    subnet_id, sg_id = _default_network(ctx)
    role_arn = _operator_role(ctx)

    not_found = f"Network connector not found: {bogus_id}"

    get_code, get_message = _error(lambda: lc.get_network_connector(Identifier=bogus_id))
    assert get_code == "ResourceNotFoundException", f"GetNetworkConnector: expected ResourceNotFoundException, got {get_code}"
    assert get_message == not_found, f"GetNetworkConnector: message {get_message!r}"

    update_code, update_message = _error(
        lambda: lc.update_network_connector(Identifier=bogus_id, Configuration=_dummy_config(subnet_id, sg_id))
    )
    assert update_code == "ResourceNotFoundException", f"UpdateNetworkConnector: expected ResourceNotFoundException, got {update_code}"
    assert update_message == not_found, f"UpdateNetworkConnector: message {update_message!r}"

    delete_code, delete_message = _error(lambda: lc.delete_network_connector(Identifier=bogus_id))
    assert delete_code == "ResourceNotFoundException", f"DeleteNetworkConnector: expected ResourceNotFoundException, got {delete_code}"
    assert delete_message == not_found, f"DeleteNetworkConnector: message {delete_message!r}"

    # positive control: a real connector remains fully reachable
    name = ctx.unique_name("sim2real-lnc-")
    created = _create_connector(
        lc, Name=name, Configuration=_dummy_config(subnet_id, sg_id), OperatorRole=role_arn, Tags={"sim2real": name}
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))
    fetched = lc.get_network_connector(Identifier=connector_id)
    assert fetched["Id"] == connector_id, f"positive control: expected Id {connector_id!r}, got {fetched.get('Id')!r}"
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


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    """Look up the run's shared network's subnet and default security group (no resources created)."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
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


OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"

_ROLE_PROPAGATION_WAIT_S = 120.0
_TRANSIENT_ROLE_MESSAGES = (
    "unable to assume the provided NetworkConnectorOperatorRole",
    "invalid ConnectorOperatorRole permissions",
)


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
    return role_arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
