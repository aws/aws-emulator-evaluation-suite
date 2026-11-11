"""capacity-provider-ops-on-missing-cluster-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "capacity-provider-ops-on-missing-cluster-not-found"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


_MI_INSTANCE_POLICY = "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
_MI_INFRA_POLICY = "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"


def _error_code(fn, *, allow_success=False):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    if not allow_success:
        raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")
    return None


def _refusal(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
        ctx.on_cleanup(lambda: _delete_cp_and_wait(ecs, cp_name, cluster))
        settle_deadline = time.monotonic() + 180
        while True:
            cp = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
            if cp.get("status") == "ACTIVE":
                return cp_name, True
            if cp.get("updateStatus") == "CREATE_FAILED" or cp.get("status") == "INACTIVE":
                return cp_name, False
            if time.monotonic() >= settle_deadline:
                return cp_name, False
            time.sleep(2)

    # No naked wait for IAM propagation: _create_once()'s own 180s settle-poll
    # already absorbs it — a too-soon create either fails synchronously (caught
    # by the 90s create-retry above) or settles to CREATE_FAILED, in which case
    # this outer loop retries with a fresh name.
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
    """Create/Describe/Update/PutClusterCapacityProviders on a nonexistent cluster return
    ClusterNotFoundException, while DeleteCapacityProvider ignores `cluster` and finds the
    provider by its unique name (a real Managed Instances provider is the cluster-validated kind)."""
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    unused_cp_name = ctx.unique_name("cp-")
    try:
        real_cluster = ecs.create_cluster(
            clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-")
        )["cluster"]
        real_cluster_name = real_cluster["clusterName"]
        ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, real_cluster_name))
        real_cp_name = _create_managed_instances_cp(ctx, ecs, real_cluster_name)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"managed-instances capacity provider setup not exercisable here: {exc}") from None

    code, message = _refusal(
        lambda: ecs.create_capacity_provider(
            name=unused_cp_name,
            cluster=bogus_cluster,
            autoScalingGroupProvider={
                "autoScalingGroupArn": (
                    f"arn:aws:autoscaling:{ctx.region}:{account_id}:autoScalingGroup:"
                    "00000000-0000-0000-0000-000000000000:autoScalingGroupName/no-such-asg"
                ),
                "managedScaling": {"status": "DISABLED"},
            },
        )
    )
    assert code == "ClusterNotFoundException", f"CreateCapacityProvider: got {code}"
    assert message == "Cluster not found.", f"CreateCapacityProvider: message {message!r}"

    code, message = _refusal(lambda: ecs.describe_capacity_providers(cluster=bogus_cluster))
    assert code == "ClusterNotFoundException", f"DescribeCapacityProviders: got {code}"
    assert message == "Cluster not found.", f"DescribeCapacityProviders: message {message!r}"

    existing_cp = ecs.describe_capacity_providers(capacityProviders=[real_cp_name])[
        "capacityProviders"
    ][0]
    existing_mi = existing_cp["managedInstancesProvider"]
    existing_ilt = existing_mi["instanceLaunchTemplate"]
    update_ilt = {
        k: existing_ilt[k]
        for k in ("ec2InstanceProfileArn", "networkConfiguration")
        if k in existing_ilt
    }
    code, message = _refusal(
        lambda: ecs.update_capacity_provider(
            name=real_cp_name,
            cluster=bogus_cluster,
            managedInstancesProvider={
                "infrastructureRoleArn": existing_mi["infrastructureRoleArn"],
                "instanceLaunchTemplate": update_ilt,
                "propagateTags": "NONE",
            },
        )
    )
    assert code == "ClusterNotFoundException", f"UpdateCapacityProvider: got {code}"
    assert message == "Cluster not found.", f"UpdateCapacityProvider: message {message!r}"

    code, message = _refusal(
        lambda: ecs.put_cluster_capacity_providers(
            cluster=bogus_cluster, capacityProviders=[], defaultCapacityProviderStrategy=[]
        )
    )
    assert code == "ClusterNotFoundException", f"PutClusterCapacityProviders: got {code}"
    assert message == "Cluster not found.", f"PutClusterCapacityProviders: message {message!r}"

    # DeleteCapacityProvider ignores `cluster` — locates by name/ARN only.
    # A Managed Instances provider is provisioned asynchronously and, while it is
    # still working through its create/update, DeleteCapacityProvider short-circuits
    # with UpdateInProgressException (a non-None code). Wait for the provider to
    # reach a settled status first, then poll the delete through any residual
    # in-progress window, over a generous budget.
    def _poll_until2(fn, pred, *, timeout_s, interval_s=5, description=""):
        deadline = time.monotonic() + timeout_s
        last = None
        while True:
            last = fn()
            if pred(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")
            time.sleep(interval_s)

    # Settled == a terminal status; a Managed Instances provider may settle to
    # ACTIVE or (empirically, in preview) INACTIVE rather than only ACTIVE.
    _poll_until2(
        lambda: ecs.describe_capacity_providers(capacityProviders=[real_cp_name])[
            "capacityProviders"
        ][0].get("status"),
        lambda s: s in ("ACTIVE", "INACTIVE"),
        timeout_s=300,
        interval_s=10,
        description="the Managed Instances capacity provider settling to a terminal status",
    )

    code = _poll_until2(
        lambda: _error_code(
            lambda: ecs.delete_capacity_provider(capacityProvider=real_cp_name, cluster=bogus_cluster),
            allow_success=True,
        ),
        lambda c: c != "UpdateInProgressException",
        timeout_s=300,
        interval_s=10,
        description="DeleteCapacityProvider is evaluated once the provider's async update settles",
    )
    assert code is None, f"DeleteCapacityProvider: expected success, got {code}"


def _delete_cp_and_wait(ecs, cp_name, cluster, timeout_s=600.0, interval_s=15.0):
    """Delete a cluster-scoped capacity provider (addressed through its cluster) and wait until it is
    gone, so the cluster can be deleted after it."""
    from botocore.exceptions import ClientError

    try:
        ecs.delete_capacity_provider(capacityProvider=cp_name, cluster=cluster)
    except ClientError as exc:
        if "does not exist" not in exc.response.get("Error", {}).get("Message", ""):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while True:
        # A cluster-scoped provider is listed through its cluster; the API takes names or a cluster, not both.
        found = [cp for cp in ecs.describe_capacity_providers(cluster=cluster).get("capacityProviders", [])
                 if cp.get("name") == cp_name]
        if not found or found[0].get("status") == "INACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity provider {cp_name} still {found[0].get('status')!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _delete_cluster_when_free(ecs, cluster, timeout_s=600.0, interval_s=15.0):
    """Delete an ECS cluster, retrying while its capacity providers, tasks or attachments still hold it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClientException", "ClusterContainsTasksException", "UpdateInProgressException",
                            "ClusterContainsServicesException", "ClusterContainsContainerInstancesException") \
                    or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
