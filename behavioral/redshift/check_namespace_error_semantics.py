"""namespace-error-semantics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-error-semantics"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Register/DeregisterNamespace reject a nonexistent ProvisionedIdentifier and a nonexistent
    ServerlessIdentifier with ClusterNotFound and their exact messages, while both calls are
    accepted for a real, available cluster."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bogus_cluster = ctx.unique_name("sim2real-nsns-nocluster-")
    bogus_namespace_id = ctx.unique_name("sim2real-nsns-badns-")

    def provisioned_id(fn):
        return fn(
            NamespaceIdentifier={"ProvisionedIdentifier": {"ClusterIdentifier": bogus_cluster}},
            ConsumerIdentifiers=[account_id],
        )

    def serverless_id(fn):
        return fn(
            NamespaceIdentifier={
                "ServerlessIdentifier": {
                    "NamespaceIdentifier": bogus_namespace_id,
                    "WorkgroupIdentifier": bogus_namespace_id,
                }
            },
            ConsumerIdentifiers=[account_id],
        )

    cluster_missing = f"Cluster {bogus_cluster} can't be found."
    workgroup_missing = (
        f'Could not find serverless workgroup for serverless workgroup owner "{account_id}" '
        f'with serverless workgroup name "{bogus_namespace_id}"'
    )

    register_cluster_code, register_cluster_message = _error(lambda: provisioned_id(redshift.register_namespace))
    assert register_cluster_code == "ClusterNotFound", (
        f"RegisterNamespace: expected ClusterNotFound, got {register_cluster_code}"
    )
    assert register_cluster_message == cluster_missing, f"RegisterNamespace: unexpected ClusterNotFound message {register_cluster_message!r}"

    register_ns_code, register_ns_message = _error(lambda: serverless_id(redshift.register_namespace))
    assert register_ns_code == "ClusterNotFound", (
        f"RegisterNamespace: expected ClusterNotFound, got {register_ns_code}"
    )
    assert register_ns_message == workgroup_missing, f"RegisterNamespace: unexpected ClusterNotFound message {register_ns_message!r}"

    deregister_cluster_code, deregister_cluster_message = _error(lambda: provisioned_id(redshift.deregister_namespace))
    assert deregister_cluster_code == "ClusterNotFound", (
        f"DeregisterNamespace: expected ClusterNotFound, got {deregister_cluster_code}"
    )
    assert deregister_cluster_message == cluster_missing, f"DeregisterNamespace: unexpected ClusterNotFound message {deregister_cluster_message!r}"

    deregister_ns_code, deregister_ns_message = _error(lambda: serverless_id(redshift.deregister_namespace))
    assert deregister_ns_code == "ClusterNotFound", (
        f"DeregisterNamespace: expected ClusterNotFound, got {deregister_ns_code}"
    )
    assert deregister_ns_message == workgroup_missing, f"DeregisterNamespace: unexpected ClusterNotFound message {deregister_ns_message!r}"

    # Positive control: the same two operations succeed against a real, available
    # cluster -- proving the four ClusterNotFound rejections above are about the
    # nonexistent target, not a universally broken RegisterNamespace/DeregisterNamespace.
    real_cluster_id = _create_available_cluster(ctx)
    real_namespace_id = {"ProvisionedIdentifier": {"ClusterIdentifier": real_cluster_id}}

    register_result = redshift.register_namespace(
        NamespaceIdentifier=real_namespace_id, ConsumerIdentifiers=[account_id]
    )
    assert register_result["Status"] in ("Registering", "Registered"), (
        f"positive control: expected Registering/Registered, got {register_result['Status']}"
    )

    # RegisterNamespace transiently moves the cluster out of "available" while the
    # registration linkage settles; wait for it to settle before deregistering, or
    # DeregisterNamespace races it and fails with InvalidClusterState.
    _wait_for_cluster_status(ctx, real_cluster_id, {"available"}, timeout_s=300)

    deregister_result = redshift.deregister_namespace(
        NamespaceIdentifier=real_namespace_id, ConsumerIdentifiers=[account_id]
    )
    assert deregister_result["Status"] in ("Deregistering", "Deregistered"), (
        f"positive control: expected Deregistering/Deregistered, got {deregister_result['Status']}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_available_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-nsns-posctl-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        ManageMasterPassword=True,
        ClusterType="single-node",
        PubliclyAccessible=False,
        ClusterSubnetGroupName=_network_redshift_subnet_group(ctx, redshift),
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    return cluster_id


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


def _delete_cluster(ctx, cluster_id: str) -> None:
    redshift = ctx.client("redshift")
    try:
        _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
    try:
        redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
        return
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(15)


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.

    The 1500 s window fits this suite's 1800 s teardown budget.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
