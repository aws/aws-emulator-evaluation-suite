"""network-connector-delete-transitions-to-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-delete-transitions-to-removed"
GROUP = "state"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkConnector on an ACTIVE connector eventually removes it (GetNetworkConnector -> NotFound)."""
    lc = ctx.client("lambda-core")
    infra = _setup_operator_role_and_vpc(ctx)

    name = ctx.unique_name("sim2real-lnc-")
    # Not every AZ offers the MicroVm compute type; the setup holds one subnet per default-VPC AZ,
    # tried in turn, and only that refusal moves on to the next one.
    for i, subnet_id in enumerate(infra["subnet_ids"]):
        try:
            created = _create_connector_with_retry(
                lc,
                name,
                _vpc_egress_config([subnet_id], [infra["sg_id"]]),
                infra["role_arn"],
            )
            break
        except ClientError as exc:
            if not _az_unsupported(exc) or i == len(infra["subnet_ids"]) - 1:
                raise
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))

    active = _poll_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda resp: resp["State"] in ("ACTIVE", "FAILED"),
        timeout_s=720,
        interval_s=15,
    )
    assert active["State"] == "ACTIVE", f"prerequisite connector never reached ACTIVE: {active['State']}"

    lc.delete_network_connector(Identifier=connector_id)

    def _get_or_none():
        try:
            return lc.get_network_connector(Identifier=connector_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return "REMOVED"
            raise

    final = _poll_until(_get_or_none, lambda v: v == "REMOVED" or v["State"] == "DELETE_FAILED", timeout_s=300, interval_s=10)
    assert final == "REMOVED", f"connector did not fully disappear, last observed state={final}"

    # A removed connector is not just absent from Get — mutating it must fail the same way,
    # not silently no-op against a dangling id.
    redelete_code, redelete_message = _error(lambda: lc.delete_network_connector(Identifier=connector_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"DeleteNetworkConnector on the already-removed id: expected ResourceNotFoundException, got {redelete_code}"
    )
    assert redelete_message == f"Network connector not found: {created['Arn']}", (
        f"DeleteNetworkConnector on the already-removed id: message {redelete_message!r}"
    )


def _vpc_egress_config(subnet_ids, sg_ids=None, protocol="IPv4"):
    cfg = {
        "VpcEgressConfiguration": {
            "SubnetIds": subnet_ids,
            "NetworkProtocol": protocol,
            "AssociatedComputeResourceTypes": ["MicroVm"],
        }
    }
    if sg_ids:
        cfg["VpcEgressConfiguration"]["SecurityGroupIds"] = sg_ids
    return cfg


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _best_effort_delete(lc, connector_id):
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises; a SUCCESS raises, because real AWS
    refuses this call."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the delete of the removed connector to be refused, but it SUCCEEDED and returned {result!r}")


def _create_connector_with_retry(lc, name, config, role_arn, timeout_s=60, interval_s=5):
    """CreateNetworkConnector can reject with the OperatorRole not yet usable: IAM's own attached-policy
    read (already polled in _setup_operator_role_and_vpc) is a different, faster-converging consistency
    domain than the role becoming assumable by lambda-core itself. Retry the create call — the only
    observable signal for that second domain — instead of guessing how long it takes.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lc.create_network_connector(Name=name, Configuration=config, OperatorRole=role_arn)
        except ClientError as exc:
            if _az_unsupported(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _az_unsupported(exc) -> bool:
    """True for the refusal of a subnet whose AZ does not offer the MicroVm compute type."""
    message = exc.response.get("Error", {}).get("Message") or ""
    return message.startswith("Availability zone ") and message.endswith(
        " is not available for compute type MicroVm"
    )


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _setup_operator_role_and_vpc(ctx, extra_security_group=False):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lnc-")

    # Network connectors are only supported in a subset of AZs, so one subnet is created in each
    # of the shared network's AZs and the caller uses the first one CreateNetworkConnector accepts.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    default_subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [default_vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    azs = sorted({(s["AvailabilityZoneId"], s["AvailabilityZone"]) for s in default_subnets})

    vpc_id = ec2.create_vpc(CidrBlock="10.199.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_ids = []
    for n, (_az_id, az) in enumerate(azs, start=1):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.199.{n}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", name)],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda subnet_id=subnet_id: ec2.delete_subnet(SubnetId=subnet_id))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda-core test",
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))

    sg_id2 = None
    if extra_security_group:
        sg_id2 = ec2.create_security_group(
            VpcId=vpc_id,
            GroupName=f"{name}-2",
            Description="sim2real lambda-core test 2",
            TagSpecifications=[_tag_spec("security-group", f"{name}-2")],
        )["GroupId"]
        ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id2))

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)
    role_arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    iam.attach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=OPERATOR_POLICY_ARN))

    def _attached():
        arns = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]]
        return OPERATOR_POLICY_ARN in arns

    _poll_until(_attached, lambda ok: ok, timeout_s=30, interval_s=2)

    return {"subnet_ids": subnet_ids, "sg_id": sg_id, "sg_id2": sg_id2, "role_arn": role_arn}



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
