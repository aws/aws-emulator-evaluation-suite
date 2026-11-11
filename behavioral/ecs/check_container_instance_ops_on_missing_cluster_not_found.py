"""container-instance-ops-on-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-instance-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Container-instance operations on a missing cluster are refused ClusterNotFoundException
    with the exact message (RegisterContainerInstance ClientException 'Cluster not found.'),
    while on a real empty cluster none of them answers cluster-not-found."""
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    fake_ci_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{bogus_cluster}/"
        "00000000000000000000000000000000"
    )

    real_cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=real_cluster)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster))
    real_fake_ci_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{real_cluster}/"
        "00000000000000000000000000000000"
    )
    cluster_not_found = "Cluster not found."

    code, message = _error(lambda: ecs.register_container_instance(cluster=real_cluster))
    assert code == "InvalidParameterException", f"RegisterContainerInstance (real cluster): got {code}"
    assert message == (
        "The identity document and identity document signature were not valid."
    ), f"RegisterContainerInstance (real cluster): got {message!r}"

    code, message = _error(lambda: ecs.register_container_instance(cluster=bogus_cluster))
    assert code == "ClientException", f"RegisterContainerInstance: got {code}"
    assert message == "Cluster not found.", f"RegisterContainerInstance: got {message!r}"

    code, _ = _error(
        lambda: ecs.deregister_container_instance(cluster=real_cluster, containerInstance=real_fake_ci_arn)
    )
    assert code != "ClusterNotFoundException", f"DeregisterContainerInstance (real cluster): got {code}"

    code, message = _error(
        lambda: ecs.deregister_container_instance(cluster=bogus_cluster, containerInstance=fake_ci_arn)
    )
    assert code == "ClusterNotFoundException", f"DeregisterContainerInstance: got {code}"
    assert message == cluster_not_found, f"DeregisterContainerInstance: got {message!r}"

    real_update = ecs.update_container_instances_state(
        cluster=real_cluster, containerInstances=[real_fake_ci_arn], status="DRAINING"
    )
    # The failure entry reports the container instance in the cluster-less ARN form.
    reported_ci_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/00000000000000000000000000000000"
    )
    real_update_failures = [(f.get("arn"), f.get("reason")) for f in real_update.get("failures", [])]
    assert real_update_failures == [(reported_ci_arn, "MISSING")], (
        "UpdateContainerInstancesState (real cluster): expected a MISSING failure for "
        f"{reported_ci_arn}, got {real_update_failures}"
    )

    code, message = _error(
        lambda: ecs.update_container_instances_state(
            cluster=bogus_cluster, containerInstances=[fake_ci_arn], status="DRAINING"
        )
    )
    assert code == "ClusterNotFoundException", f"UpdateContainerInstancesState: got {code}"
    assert message == cluster_not_found, f"UpdateContainerInstancesState: got {message!r}"

    real_describe = ecs.describe_container_instances(
        cluster=real_cluster, containerInstances=[real_fake_ci_arn]
    )
    assert not real_describe.get("containerInstances"), (
        f"DescribeContainerInstances (real cluster): expected no instances, got {real_describe}"
    )
    real_failures = real_describe.get("failures", [])
    assert real_failures and real_failures[0].get("arn") == real_fake_ci_arn, (
        f"DescribeContainerInstances (real cluster): expected a failure entry for "
        f"{real_fake_ci_arn}, got {real_failures}"
    )

    code, message = _error(
        lambda: ecs.describe_container_instances(cluster=bogus_cluster, containerInstances=[fake_ci_arn])
    )
    assert code == "ClusterNotFoundException", f"DescribeContainerInstances: got {code}"
    assert message == cluster_not_found, f"DescribeContainerInstances: got {message!r}"

    real_list = ecs.list_container_instances(cluster=real_cluster)
    assert real_list.get("containerInstanceArns") == [], (
        f"ListContainerInstances (real cluster): expected empty, got {real_list.get('containerInstanceArns')}"
    )

    code, message = _error(lambda: ecs.list_container_instances(cluster=bogus_cluster))
    assert code == "ClusterNotFoundException", f"ListContainerInstances: got {code}"
    assert message == cluster_not_found, f"ListContainerInstances: got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
