"""network-connector-update-pending-conflict-then-active-success."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-connector-update-pending-conflict-then-active-success"
GROUP = "state"
SERVICES = ["lambda-core"]

OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaNetworkConnectorOperatorPolicy"
# Measured on real AWS: CreateNetworkConnector rejects a freshly-attached OperatorRole with this
# message until the policy attachment propagates cross-service; there is no separate readiness
# signal, so this is the observable condition the retry below is bounded on.
_ROLE_NOT_PROPAGATED = "invalid ConnectorOperatorRole permissions"
_UNASSUMABLE = (
    "The service is unable to assume the provided NetworkConnectorOperatorRole. "
    "Please verify the trust policy on the role."
)
_ROLE_PROPAGATION_WAIT_S = 120.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNetworkConnector is rejected while PENDING, then succeeds (LastUpdateStatus Successful) once ACTIVE."""
    lc = ctx.client("lambda-core")
    infra = _setup_operator_role_and_vpc(ctx, extra_security_group=True)

    name = ctx.unique_name("sim2real-lnc-")
    created = _create_connector_with_role_propagation_retry(
        lc,
        Name=name,
        Configuration=_vpc_egress_config([infra["subnet_id"]], [infra["sg_id"]]),
        OperatorRole=infra["role_arn"],
    )
    connector_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete(lc, connector_id))
    # PENDING is the window this check holds: it lasts minutes on real AWS, and the refusal
    # below is issued inside it, immediately after the create.
    assert created["State"] == "PENDING", f"a fresh connector reported State {created['State']!r}, expected 'PENDING'"

    # --- negative: updating while still PENDING is a resource conflict ---
    code, message = _error(
        lambda: lc.update_network_connector(
            Identifier=connector_id,
            Configuration=_vpc_egress_config([infra["subnet_id"]], [infra["sg_id"], infra["sg_id2"]]),
        )
    )
    assert code == "ResourceConflictException", f"expected ResourceConflictException while PENDING, got {code}"
    expected = (
        f"Network connector {connector_id} is in state Pending and cannot be updated. "
        "Only ACTIVE connectors can be updated."
    )
    assert message == expected, f"PENDING update refused with {message!r}, expected {expected!r}"

    unchanged = lc.get_network_connector(Identifier=connector_id)
    sg_ids_after_rejected_update = unchanged["Configuration"]["VpcEgressConfiguration"].get("SecurityGroupIds", [])
    assert sg_ids_after_rejected_update == [infra["sg_id"]], (
        "rejected update while PENDING must not change the persisted configuration"
    )

    # --- wait for ACTIVE, then a real update must succeed ---
    active = _poll_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda resp: resp["State"] in ("ACTIVE", "FAILED"),
        timeout_s=720,
        interval_s=15,
    )
    assert active["State"] == "ACTIVE", f"prerequisite connector never reached ACTIVE: {active['State']}"
    # The model documents Version as "incremented on each update", but AWS does not
    # populate it here, before or after a successful update. LastModified is the
    # signal the service actually reports, so that is what advancing-state is measured against.
    modified_before = active.get("LastModified")

    lc.update_network_connector(
        Identifier=connector_id,
        Configuration=_vpc_egress_config([infra["subnet_id"]], [infra["sg_id"], infra["sg_id2"]]),
    )

    updated = _poll_until(
        lambda: lc.get_network_connector(Identifier=connector_id),
        lambda resp: resp["LastUpdateStatus"] in ("Successful", "Failed"),
        timeout_s=300,
        interval_s=10,
    )
    assert updated["LastUpdateStatus"] == "Successful", (
        f"expected LastUpdateStatus=Successful, got {updated['LastUpdateStatus']} "
        f"reason={updated.get('LastUpdateStatusReason')}"
    )
    final_sg_ids = set(updated["Configuration"]["VpcEgressConfiguration"].get("SecurityGroupIds", []))
    assert final_sg_ids == {infra["sg_id"], infra["sg_id2"]}, f"security groups not updated: {final_sg_ids}"
    modified_after = updated.get("LastModified")
    assert modified_after is not None, "expected LastModified to be present once a connector has been updated"
    assert modified_before is None or modified_after > modified_before, (
        f"LastModified did not advance after a successful update: "
        f"before={modified_before!r} after={modified_after!r}"
    )

    # The connector's ENIs block the VPC teardown, so it is deleted and confirmed gone here.
    _delete_and_wait_gone(lc, connector_id)


# ===== helpers =====

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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a SUCCESS raises."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


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


def _create_connector_with_role_propagation_retry(lc, **kwargs):
    """CreateNetworkConnector, retrying only the IAM-propagation rejection.

    Bounded by _ROLE_PROPAGATION_WAIT_S and gated on the exact refusal message real AWS returns
    for an unpropagated OperatorRole; any other failure (or exhausting the deadline) re-raises.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_WAIT_S
    while True:
        try:
            return lc.create_network_connector(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            message = err.get("Message") or ""
            transient = message == _UNASSUMABLE or _ROLE_NOT_PROPAGATED in message
            if not transient or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _best_effort_delete(lc, connector_id):
    try:
        lc.delete_network_connector(Identifier=connector_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _usable_zone(ec2):
    """The alphabetically-first available zone: MicroVm network connectors are supported in only a
    subset of AZs, so the subnet is not left to EC2's default AZ placement."""
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


def _setup_operator_role_and_vpc(ctx, extra_security_group=False):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lnc-")

    vpc_id = ec2.create_vpc(CidrBlock="10.199.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.199.1.0/24", AvailabilityZone=_usable_zone(ec2), TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda-core test",
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    sg_id2 = None
    if extra_security_group:
        sg_id2 = ec2.create_security_group(
            VpcId=vpc_id,
            GroupName=f"{name}-2",
            Description="sim2real lambda-core test 2",
            TagSpecifications=[_tag_spec("security-group", f"{name}-2")],
        )["GroupId"]
        ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id2))

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

    return {"subnet_id": subnet_id, "sg_id": sg_id, "sg_id2": sg_id2, "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
