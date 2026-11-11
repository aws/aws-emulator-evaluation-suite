"""create-cluster-service-connect-namespace-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-cluster-service-connect-namespace-validation"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

_SIM2REAL_TAG = {"Key": "sim2real:managed", "Value": "true"}
_ECS_SIM2REAL_TAG = {"key": "sim2real:managed", "value": "true"}


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_cluster_when_idle(ecs, cluster, timeout_s=180):
    """Delete an ECS cluster, waiting out the busy window while its Service Connect
    attachments are still updating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            busy = exc.response.get("Error", {}).get("Code") == "UpdateInProgressException"
            if not busy or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_own_vpc(ctx):
    """Create a dedicated VPC for this run rather than depending on an ambient
    default VPC, which a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [_SIM2REAL_TAG]}],
    )["Vpc"]["VpcId"]

    def _delete_vpc():
        deadline = time.monotonic() + 45
        while True:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                return
            except ClientError as exc:
                transient = exc.response.get("Error", {}).get("Code") == "DependencyViolation"
                if not transient or time.monotonic() >= deadline:
                    raise
                time.sleep(3)

    ctx.on_cleanup(_delete_vpc)
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=30,
        interval_s=2,
        description="the newly created VPC becomes available",
    )
    return vpc_id


def _create_private_dns_namespace(ctx, *, timeout_s=120):
    """Create a Cloud Map private DNS namespace in a VPC this check created
    itself; waits for the async CreateNamespace operation to finish and
    returns the namespace id.
    """
    sd = ctx.client("servicediscovery")
    vpc_id = _create_own_vpc(ctx)
    ns_name = f"{ctx.unique_name('sim2real-behav-ecs-ns-')}.local"
    op_id = sd.create_private_dns_namespace(
        Name=ns_name, Vpc=vpc_id, Tags=[_SIM2REAL_TAG]
    )["OperationId"]
    op = _poll_until(
        lambda: sd.get_operation(OperationId=op_id)["Operation"],
        lambda o: o["Status"] in ("SUCCESS", "FAIL"),
        timeout_s=timeout_s,
        interval_s=5,
        description="Cloud Map CreateNamespace operation completes",
    )
    if op["Status"] != "SUCCESS":
        raise AssertionError(f"Cloud Map namespace creation failed: {op.get('ErrorMessage')}")
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=namespace_id))
    return namespace_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster with serviceConnectDefaults naming a Cloud Map namespace returns and
    describes it; a namespace name that does not resolve is also accepted, stored as a distinct
    reference whose GetNamespace is refused NamespaceNotFound with an empty message."""
    ecs = ctx.client("ecs")
    sd = ctx.client("servicediscovery")
    namespace_id = _create_private_dns_namespace(ctx)
    namespace_arn = sd.get_namespace(Id=namespace_id)["Namespace"]["Arn"]

    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    cluster = ecs.create_cluster(
        clusterName=name,
        serviceConnectDefaults={"namespace": namespace_arn},
        tags=[_ECS_SIM2REAL_TAG],
    )["cluster"]
    ctx.on_cleanup(lambda: _delete_cluster_when_idle(ecs, name))
    assert cluster.get("serviceConnectDefaults", {}).get("namespace") == namespace_arn, (
        f"expected the cluster to reflect the real namespace, got {cluster.get('serviceConnectDefaults')}"
    )
    described = ecs.describe_clusters(clusters=[name])["clusters"][0]
    assert described.get("serviceConnectDefaults", {}).get("namespace") == namespace_arn, (
        "expected an independent DescribeClusters read to durably reflect the real namespace, "
        f"got {described.get('serviceConnectDefaults')}"
    )

    # ECS does not resolve the serviceConnectDefaults namespace at CreateCluster time, so a
    # namespace name that does not resolve is accepted. The name is not stored verbatim: ECS
    # stores a Cloud-Map-ARN-shaped reference whose namespace id does not exist (GetNamespace
    # refuses it), distinct from the real namespace above.
    bogus_cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    bogus_namespace = ctx.unique_name("no-such-namespace-")
    try:
        bogus_cluster = ecs.create_cluster(
            clusterName=bogus_cluster_name,
            serviceConnectDefaults={"namespace": bogus_namespace},
            tags=[_ECS_SIM2REAL_TAG],
        )["cluster"]
        create_error = None
    except ClientError as exc:
        bogus_cluster = {}
        create_error = exc.response.get("Error", {}).get("Code")
    ctx.on_cleanup(lambda: _delete_cluster_when_idle(ecs, bogus_cluster_name))
    assert create_error is None, (
        f"real ECS accepts a not-yet-resolvable Service Connect namespace at CreateCluster time, "
        f"got {create_error}"
    )
    created_ns_ref = bogus_cluster.get("serviceConnectDefaults", {}).get("namespace")

    described_bogus = ecs.describe_clusters(clusters=[bogus_cluster_name])["clusters"][0]
    resolved_ns = described_bogus.get("serviceConnectDefaults", {}).get("namespace")
    assert resolved_ns == created_ns_ref, (
        "expected an independent DescribeClusters read to durably reflect exactly what "
        f"CreateCluster's own response returned, got create={created_ns_ref!r} describe={resolved_ns!r}"
    )
    assert resolved_ns and resolved_ns != namespace_arn, (
        f"expected the not-yet-resolvable namespace reference to stay distinct from the real "
        f"namespace {namespace_arn!r}, got {resolved_ns!r}"
    )
    resolved_id = resolved_ns.rsplit("/", 1)[-1]
    lookup_code, lookup_message = _error(lambda: sd.get_namespace(Id=resolved_id))
    assert lookup_code == "NamespaceNotFound", (
        "expected the ECS-normalized namespace reference to remain genuinely unresolvable in "
        f"Cloud Map, got {lookup_code}"
    )
    # AWS returns NamespaceNotFound for this lookup with an empty message body.
    expected_message = ""
    assert lookup_message == expected_message, (
        f"expected message {expected_message!r}, got {lookup_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
