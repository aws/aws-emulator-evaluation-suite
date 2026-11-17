"""gateway-associates-and-disassociates-from-cluster."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-associates-and-disassociates-from-cluster"
GROUP = "gateway"
SERVICES = ["ecs", "iam"]

_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRoleForGatewayHostSharedALB"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _create_infra_role(ctx, iam) -> str:
    """An IAM role ecs.amazonaws.com can assume, with the gateway infrastructure policy."""
    name = ctx.unique_name("sim2real-behav-ecsgw-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_INFRA_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_INFRA_POLICY))
    return arn


def _create_gateway(ecs, *, name: str, role_arn: str, timeout_s: float = 90.0) -> dict:
    """CreateGateway, retried while the freshly created infrastructure role or its attached
    policy still propagates through IAM (ECS cannot yet assume or use it)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ecs.create_gateway(
                name=name,
                infrastructureRoleArn=role_arn,
                deletionProtection=False,
                configuration={"hostSharedAlb": {}},
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            message = err.get("Message") or ""
            not_ready = code == "AccessDeniedException" or (
                code == "ClientException" and "is not authorized to perform" in message
            )
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _ignore_not_found(fn, *codes: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A created gateway is ACTIVE and visible to ListGateways; associating it with a cluster
    is immediate, and disassociating one with no gateway routes removes the association."""
    ecs = ctx.client("ecs")
    iam = ctx.client("iam")

    role_arn = _create_infra_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-behav-ecsgw-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    missing_cluster_name = ctx.unique_name("sim2real-behav-ecsgw-nocluster-")

    gw_name = ctx.unique_name("sim2real-behav-ecsgw-")
    created = _create_gateway(ecs, name=gw_name, role_arn=role_arn)
    gateway_arn = created["gatewayArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: ecs.delete_gateway(gateway=gw_name), "GatewayNotFoundException", "AccessDeniedException"
        )
    )
    assert created["status"] == "ACTIVE", (
        f"expected a freshly created gateway to be ACTIVE, got {created['status']!r}"
    )
    assert created["name"] == gw_name, f"expected name {gw_name!r}, got {created['name']!r}"

    # Independent read: ListGateways proves the create through a different operation.
    listed = ecs.list_gateways(names=[gw_name])["gateways"]
    assert len(listed) == 1, f"expected exactly one gateway named {gw_name!r}, got {listed!r}"
    assert listed[0]["gatewayArn"] == gateway_arn, (
        f"ListGateways returned {listed[0]['gatewayArn']!r}, expected {gateway_arn!r}"
    )
    assert listed[0]["status"] == "ACTIVE", f"expected ACTIVE in ListGateways, got {listed[0]['status']!r}"

    # A cluster that does not exist is rejected, and the gateway stays unassociated.
    code, message = _error(
        lambda: ecs.associate_gateway_with_cluster(gateway=gw_name, cluster=missing_cluster_name)
    )
    assert code == "ClusterNotFoundException", (
        f"expected ClusterNotFoundException for a missing cluster, got {code}: {message!r}"
    )
    assert message == "Cluster not found.", f"unexpected message: {message!r}"

    assoc = ecs.associate_gateway_with_cluster(gateway=gw_name, cluster=cluster_name)
    assert assoc["status"] == "ACTIVE", (
        f"expected ACTIVE associating a gateway with no pending routes, got {assoc['status']!r}"
    )
    assert assoc["gatewayArn"] == gateway_arn, f"unexpected gatewayArn {assoc['gatewayArn']!r}"
    cluster_arn = assoc["clusterArn"]

    def _associations():
        return ecs.list_gateway_cluster_associations(gateway=gw_name)["gatewayClusterAssociations"]

    active = [a for a in _associations() if a["clusterArn"] == cluster_arn]
    assert len(active) == 1, f"expected one association for {cluster_arn!r}, got {active!r}"
    assert active[0]["status"] == "ACTIVE", f"expected ACTIVE association, got {active[0]['status']!r}"

    disassoc = ecs.disassociate_gateway_from_cluster(gateway=gw_name, cluster=cluster_name)
    assert disassoc["status"] == "INACTIVE", (
        f"expected disassociating a gateway with no gateway routes to complete at once as "
        f"INACTIVE, got {disassoc['status']!r}"
    )

    def _still_listed():
        return any(a["clusterArn"] == cluster_arn for a in _associations())

    _poll_until(
        lambda: not _still_listed(),
        lambda gone: gone,
        description=f"the association with {cluster_arn!r} to leave ListGatewayClusterAssociations",
    )

    ecs.delete_gateway(gateway=gw_name)
    remaining = ecs.list_gateways(names=[gw_name])["gateways"]
    assert remaining == [], f"expected the deleted gateway to be gone from ListGateways, got {remaining!r}"

    code, message = _error(lambda: ecs.describe_gateway(gateway=gw_name))
    assert code == "AccessDeniedException", (
        f"expected a deleted gateway to read back as AccessDeniedException, got {code}: {message!r}"
    )
    assert message == (
        "You are not authorized to perform this operation on the specified gateway, or it does not exist."
    ), f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
