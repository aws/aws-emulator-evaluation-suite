"""op-contract-update-cluster."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-cluster"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster sets containerInsights as DescribeClusters confirms and stores a bare
    serviceConnectDefaults namespace name as the ARN of a Cloud Map namespace created under that
    name; a missing cluster is refused ClusterNotFoundException."""
    ecs = ctx.client("ecs")
    sd = ctx.client("servicediscovery")

    cluster_name = ctx.unique_name("sim2real-ecs-upcluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _retry_while_updating(lambda: ecs.delete_cluster(cluster=cluster_name)))

    updated = ecs.update_cluster(
        cluster=cluster_name,
        settings=[{"name": "containerInsights", "value": "enabled"}],
    )["cluster"]
    assert {"name": "containerInsights", "value": "enabled"} in updated["settings"], updated["settings"]

    # DescribeClusters only returns the "settings" field when explicitly requested via
    # the "include" parameter; without it the field is omitted from the response.
    described = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_name], include=["SETTINGS"])["clusters"][0],
        lambda d: {"name": "containerInsights", "value": "enabled"} in d.get("settings", []),
    )
    assert {"name": "containerInsights", "value": "enabled"} in described["settings"], described["settings"]

    sc_namespace_name = ctx.unique_name("sim2real-ecs-svcconnect-ns-")
    updated_sc = ecs.update_cluster(
        cluster=cluster_name,
        serviceConnectDefaults={"namespace": sc_namespace_name},
    )["cluster"]
    persisted_arn = updated_sc.get("serviceConnectDefaults", {}).get("namespace")
    assert persisted_arn and persisted_arn != sc_namespace_name and ":namespace/ns-" in persisted_arn, (
        f"expected UpdateCluster to auto-provision a Cloud Map namespace ARN, not persist the bare "
        f"name verbatim, got {updated_sc.get('serviceConnectDefaults')}"
    )
    namespace_id = persisted_arn.rsplit("/", 1)[-1]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=namespace_id))

    # Independent read at a different service: Cloud Map itself confirms a namespace with the
    # exact given name now exists at that id -- this is the auto-provisioning, not an echo.
    # The namespace ECS just auto-created is provisioned asynchronously in Cloud Map, so a
    # GetNamespace immediately after UpdateCluster can still 404 -- bounded retry for that.
    created_namespace = _poll_until_found(lambda: sd.get_namespace(Id=namespace_id)["Namespace"], timeout=90.0)
    assert created_namespace["Name"] == sc_namespace_name, created_namespace

    described_after = _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_name])["clusters"][0],
        lambda d: d.get("serviceConnectDefaults", {}).get("namespace") == persisted_arn,
    )
    assert described_after.get("serviceConnectDefaults", {}).get("namespace") == persisted_arn, (
        described_after.get("serviceConnectDefaults")
    )

    code, message = _error(lambda: ecs.update_cluster(cluster="sim2real-nonexistent-cluster-8843"))
    assert code == "ClusterNotFoundException", code
    assert message == "Cluster not found.", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(fetch, predicate, timeout=30.0, interval=1.0):
    import time
    deadline = time.monotonic() + timeout
    result = fetch()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval)
        result = fetch()
    return result


def _poll_until_found(fetch, timeout=30.0, interval=1.0):
    from botocore.exceptions import ClientError
    import time
    deadline = time.monotonic() + timeout
    while True:
        try:
            return fetch()
        except ClientError as e:
            if e.response["Error"]["Code"] != "NamespaceNotFound" or time.monotonic() >= deadline:
                raise
            time.sleep(interval)


def _retry_while_updating(fn, timeout_s=180.0, interval_s=5.0):
    """Call fn() until the cluster's capacity-provider attachment settles: ECS refuses cluster
    updates and deletes with UpdateInProgressException until then."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UpdateInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
