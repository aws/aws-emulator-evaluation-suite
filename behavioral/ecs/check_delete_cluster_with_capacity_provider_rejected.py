"""delete-cluster-with-capacity-provider-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "delete-cluster-with-capacity-provider-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


_MI_INSTANCE_POLICY = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_MI_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"


def _error_response(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response
    return None


def _delete_capacity_provider_if_present(ecs, cp_name):
    """Teardown: a cluster-scoped provider is already gone once its cluster is deleted."""
    try:
        ecs.delete_capacity_provider(capacityProvider=cp_name)
    except ClientError as exc:
        if exc.response["Error"].get("Message", "") != (
            "The specified capacity provider does not exist. Specify a valid name or ARN and try again."
        ):
            raise


def _poll_until(fn, pred, *, timeout_s, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _create_managed_instances_cp(ctx, ecs, cluster):
    iam = ctx.client("iam")
    subnets, sg = _fargate_network(ctx)

    trust_ec2 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    instance_role = ctx.unique_name("ecsInstanceRole-")[:64]
    instance_role_arn = iam.create_role(
        RoleName=instance_role, AssumeRolePolicyDocument=json.dumps(trust_ec2)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=instance_role))
    iam.attach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=instance_role, PolicyArn=_MI_INSTANCE_POLICY))
    iam.create_instance_profile(InstanceProfileName=instance_role)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role))
    iam.add_role_to_instance_profile(InstanceProfileName=instance_role, RoleName=instance_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=instance_role, RoleName=instance_role
        )
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=instance_role)["InstanceProfile"]["Arn"]

    trust_ecs = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    infra_role = ctx.unique_name("ecsInfra-")[:64]
    infra_role_arn = iam.create_role(
        RoleName=infra_role, AssumeRolePolicyDocument=json.dumps(trust_ecs)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=infra_role))
    iam.attach_role_policy(RoleName=infra_role, PolicyArn=_MI_INFRA_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=infra_role, PolicyArn=_MI_INFRA_POLICY))
    iam.put_role_policy(
        RoleName=infra_role,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=infra_role, PolicyName="inline"))

    # ECS assumes the just-created infrastructure role to provision the Managed
    # Instances fleet. A freshly created role's trust/attached policies are not
    # immediately usable (IAM eventual consistency), so a CP created too soon
    # settles to CREATE_FAILED ("ServiceAccessDeniedException for
    # ECSInfrastructureRole"). Let IAM propagate first, then create and wait for
    # the async provision to settle; if it still fails on role access, recreate
    # with a fresh name over a generous budget.
    def _create_once():
        cp_name = ctx.unique_name("cp-")
        create_deadline = time.monotonic() + 90
        while True:
            try:
                ecs.create_capacity_provider(
                    name=cp_name,
                    cluster=cluster,
                    managedInstancesProvider={
                        "infrastructureRoleArn": infra_role_arn,
                        "instanceLaunchTemplate": {
                            "ec2InstanceProfileArn": profile_arn,
                            "networkConfiguration": {"subnets": subnets[:1], "securityGroups": [sg]},
                            "monitoring": "basic",
                        },
                    },
                )
                break
            except ClientError as exc:
                if time.monotonic() >= create_deadline:
                    raise AssertionError(
                        f"could not provision a Managed Instances capacity provider: {exc}"
                    ) from None
                time.sleep(2)
        ctx.on_cleanup(lambda: _delete_capacity_provider_if_present(ecs, cp_name))
        settle_deadline = time.monotonic() + 180
        while True:
            # DescribeCapacityProviders is eventually consistent right after
            # CreateCapacityProvider — the provider can be briefly absent, so
            # tolerate an empty list instead of indexing [0] and keep polling.
            _cps = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
            cp = _cps[0] if _cps else {}
            if cp.get("status") == "ACTIVE":
                return cp_name, True
            if cp.get("updateStatus") == "CREATE_FAILED" or cp.get("status") == "INACTIVE":
                return cp_name, False
            if time.monotonic() >= settle_deadline:
                return cp_name, False
            time.sleep(2)

    attempts_deadline = time.monotonic() + 210
    cp_name, ok = _create_once()
    while not ok:
        if time.monotonic() >= attempts_deadline:
            raise AssertionError(
                "Managed Instances capacity provider repeatedly settled to CREATE_FAILED "
                "(infrastructure-role access); not exercisable in this account"
            )
        time.sleep(2)
        cp_name, ok = _create_once()
    return cp_name


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster on a cluster with an attached cluster-scoped (Managed Instances) capacity
    provider is rejected with ClientException ("The Cluster cannot be deleted while Cluster Scoped
    Capacity Providers are attached..."), while a plain cluster deletes cleanly."""
    ecs = ctx.client("ecs")

    # Positive control: DeleteCluster succeeds on an ordinary cluster with no
    # capacity-provider association, proving the account/credentials are
    # otherwise healthy for this call before the negative below is exercised.
    control_cluster = ctx.unique_name("sim2real-behav-ecs-control-")
    ecs.create_cluster(clusterName=control_cluster)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=control_cluster))
    ecs.delete_cluster(cluster=control_cluster)
    control_deleted = _poll_until(
        lambda: ecs.describe_clusters(clusters=[control_cluster])["clusters"][0],
        lambda c: c["status"] == "INACTIVE",
        timeout_s=30,
        interval_s=2,
    )
    assert control_deleted["status"] == "INACTIVE", "positive control: plain DeleteCluster did not succeed"

    try:
        cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
        cluster_name = cluster["clusterName"]
        # Registered here — chronologically FIRST, so it runs LAST under LIFO,
        # after the capacity-provider detach/delete/IAM/network cleanups below
        # have all had their turn and the async CP-detach has had the most
        # possible time to settle. DeleteCluster keeps refusing with the same
        # ClientException asserted above until the detach actually lands, so a
        # single un-retried attempt here is racy; retry it, bounded, within
        # what remains of the shared 60s cleanup budget.
        def _cleanup_delete_cluster():
            deadline = time.monotonic() + 30
            while True:
                resp = _error_response(lambda: ecs.delete_cluster(cluster=cluster_name))
                if resp is None or time.monotonic() >= deadline:
                    return
                time.sleep(3)

        ctx.on_cleanup(_cleanup_delete_cluster)
        cp_name = _create_managed_instances_cp(ctx, ecs, cluster_name)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"managed-instances capacity provider setup not exercisable here: {exc}") from None

    # A Managed Instances capacity provider is created asynchronously; it must
    # settle to a terminal status before PutClusterCapacityProviders will accept
    # it. In preview it settles to ACTIVE or (empirically) INACTIVE rather than
    # only ACTIVE, so accept either terminal state as "ready".
    _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0].get(
            "status"
        ),
        lambda s: s in ("ACTIVE", "INACTIVE"),
        timeout_s=180,
        interval_s=5,
    )
    ecs.put_cluster_capacity_providers(
        cluster=cluster_name,
        capacityProviders=[cp_name],
        defaultCapacityProviderStrategy=[{"capacityProvider": cp_name, "weight": 1}],
    )
    # Detach before returning so cleanup's DeleteCluster/DeleteCapacityProvider succeed.
    ctx.on_cleanup(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=cluster_name, capacityProviders=[], defaultCapacityProviderStrategy=[]
        )
    )
    _poll_until(
        lambda: ecs.describe_clusters(clusters=[cluster_name])["clusters"][0].get("capacityProviders", []),
        lambda cps: cp_name in cps,
        timeout_s=30,
        interval_s=2,
    )

    resp = _poll_until(
        lambda: _error_response(lambda: ecs.delete_cluster(cluster=cluster_name)),
        lambda r: (r or {}).get("Error", {}).get("Code") != "UpdateInProgressException",
        timeout_s=60,
        interval_s=5,
    )
    assert resp is not None, "DeleteCluster: expected a rejection, but the call SUCCEEDED"
    code = resp["Error"]["Code"]
    message = resp["Error"].get("Message", "")
    assert code == "ClientException", (
        f"DeleteCluster: expected ClientException, got {code} (message={message!r})"
    )
    assert message == "The Cluster cannot be deleted while Cluster Scoped Capacity Providers are attached to the cluster.", f"DeleteCluster: expected the exact capacity-provider message, got {message!r}"

    # Effect absent, via an independent read: the cluster must still exist and
    # still carry the capacity-provider association DeleteCluster refused to drop.
    still_there = ecs.describe_clusters(clusters=[cluster_name])["clusters"][0]
    assert still_there["status"] != "INACTIVE", "cluster should not have been deleted"
    assert cp_name in still_there.get("capacityProviders", []), (
        "capacity-provider association was dropped by the rejected DeleteCluster"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
