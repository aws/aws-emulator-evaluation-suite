"""cancel-update-completed-update-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cancel-update-completed-update-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]

_CLUSTER_WAIT_TIMEOUT_S = 20 * 60
_CLUSTER_POLL_INTERVAL_S = 2
_UPDATE_WAIT_TIMEOUT_S = 10 * 60
_UPDATE_POLL_INTERVAL_S = 10


_NOT_CANCELLABLE = (
    "InvalidParameterException",
    "Update is not in a cancellable state. Supported update types: VersionRollback",
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelUpdate on an update that already reached Successful fails InvalidParameterException and
    leaves it Successful, while the logging change took effect and a fresh update still succeeds."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)

    update = eks.update_cluster_config(
        name=cluster_name,
        logging={"clusterLogging": [{"types": ["api"], "enabled": True}]},
    )["update"]
    update_id = update["id"]
    assert update["type"] == "LoggingUpdate", update

    # Positive control: the logging update genuinely completes and takes effect.
    final = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=_UPDATE_WAIT_TIMEOUT_S,
        interval_s=_UPDATE_POLL_INTERVAL_S,
    )
    assert final["status"] == "Successful", f"logging update ended in {final['status']}: {final.get('errors')}"

    cluster_logging = eks.describe_cluster(name=cluster_name)["cluster"]["logging"]["clusterLogging"]
    api_setup = next(setup for setup in cluster_logging if "api" in setup["types"])
    assert api_setup["enabled"] is True, cluster_logging

    # Break exactly one thing: try to cancel an update that has already completed.
    # CancelUpdate is currently only supported for VersionRollback update types on
    # EKS Auto Mode clusters mid node-rollback; a completed LoggingUpdate on a plain
    # cluster is rejected as an invalid parameter (empirically confirmed on real AWS,
    # NOT the InvalidStateException documented for upgrade-readiness rejections).
    code = _expect_error(lambda: eks.cancel_update(name=cluster_name, updateId=update_id))
    assert code == _NOT_CANCELLABLE, code

    # Effect absent: the update's terminal status did not change to Cancelled.
    unchanged = eks.describe_update(name=cluster_name, updateId=update_id)["update"]
    assert unchanged["status"] == "Successful", unchanged

    # Restore leg: the rejected cancel did not disable the update mechanism on this
    # cluster -- a fresh, unrelated config update still runs to completion.
    second = eks.update_cluster_config(
        name=cluster_name,
        logging={"clusterLogging": [{"types": ["api"], "enabled": False}]},
    )["update"]
    assert second["id"] != update_id, second
    second_final = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=second["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=_UPDATE_WAIT_TIMEOUT_S,
        interval_s=_UPDATE_POLL_INTERVAL_S,
    )
    assert second_final["status"] == "Successful", (
        f"update mechanism should still work after the rejected cancel, got {second_final['status']}: "
        f"{second_final.get('errors')}"
    )


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _expect_error(fn):
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS refuses must not be mistaken for a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    assert len(az_names) >= 2, "region needs at least two availability zones"

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _delete_cluster_and_wait(ctx, name: str) -> None:
    eks = ctx.client("eks")
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + _CLUSTER_WAIT_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(_CLUSTER_POLL_INTERVAL_S)
    raise AssertionError(f"EKS cluster {name} still exists {_CLUSTER_WAIT_TIMEOUT_S}s after DeleteCluster")


def _retry_delete(fn) -> None:
    """Teardown delete (fn retries DependencyViolation itself): already gone is fine, anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _create_active_cluster(ctx) -> str:
    eks = ctx.client("eks")
    subnet_ids = _create_network(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")

    # The just-created role is rejected until IAM propagates it: retry every 2 s up to 80 s,
    # capped by the run's remaining time.
    deadline = time.monotonic() + 80.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"Name": name, "sim2real:managed": "true"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, name))

    active = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_WAIT_TIMEOUT_S,
        interval_s=_CLUSTER_POLL_INTERVAL_S,
    )
    assert active["status"] == "ACTIVE", f"cluster ended in status {active['status']}"
    return name


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 540.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
