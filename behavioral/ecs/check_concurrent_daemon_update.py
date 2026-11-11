"""concurrent-daemon-update."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-daemon-update"
GROUP = 'concurrency'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnets(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _default_sg(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return sgs[0]["GroupId"]


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _run_concurrent(fns, *, timeout_s=60):
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _create_iam_role(ctx, iam, name_prefix, trust_service, *, managed_policy_arns=(), inline_policy=None):
    role_name = ctx.unique_name(name_prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = resp["Role"]["Arn"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_name, role_arn


def _create_managed_instances_capacity_provider(ctx, ecs, cluster_name):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    instance_role_name, instance_role_arn = _create_iam_role(
        ctx,
        iam,
        "ecsInstanceRole-",
        "ec2.amazonaws.com",
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonECSInstanceRolePolicyForManagedInstances"
        ],
    )
    iam.create_instance_profile(InstanceProfileName=instance_role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=instance_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=instance_role_name, RoleName=instance_role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=instance_role_name, RoleName=instance_role_name
        )
    )
    profile_arn = iam.get_instance_profile(InstanceProfileName=instance_role_name)["InstanceProfile"][
        "Arn"
    ]

    infra_inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": instance_role_arn}],
    }
    _infra_role_name, infra_role_arn = _create_iam_role(
        ctx,
        iam,
        "ecsInfra-",
        "ecs.amazonaws.com",
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonECSInfrastructureRolePolicyForManagedInstances"
        ],
        inline_policy=infra_inline_policy,
    )

    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)

    def _try_create(cp_name):
        try:
            ecs.create_capacity_provider(
                name=cp_name,
                cluster=cluster_name,
                managedInstancesProvider={
                    "infrastructureRoleArn": infra_role_arn,
                    "instanceLaunchTemplate": {
                        "ec2InstanceProfileArn": profile_arn,
                        "networkConfiguration": {"subnets": subnets[:1], "securityGroups": [sg]},
                        "monitoring": "basic",
                    },
                },
            )
            return True
        except Exception as exc:  # noqa: BLE001 — IAM propagation lag surfaces as a ClientError
            return exc

    # ECS can assume the new infrastructure role before IAM has propagated it; that provider ends
    # CREATE_FAILED with ServiceAccessDeniedException and never recovers, so a fresh one is created.
    attempts_deadline = time.monotonic() + 240
    while True:
        cp_name = ctx.unique_name("sim2real-behav-ecs-cp-mi-")
        _poll_until(
            lambda n=cp_name: _try_create(n),
            lambda r: r is True,
            timeout_s=90,
            interval_s=10,
            description="IAM infra/instance roles propagate enough for CreateCapacityProvider",
        )
        ctx.on_cleanup(lambda n=cp_name: _delete_capacity_provider_if_present(ecs, n, cluster_name))
        cp_desc = _poll_until(
            lambda n=cp_name: ecs.describe_capacity_providers(capacityProviders=[n])["capacityProviders"][0],
            lambda cp: cp["status"] == "ACTIVE" or cp.get("updateStatus") == "CREATE_FAILED",
            timeout_s=90,
            interval_s=3,
            description="managed-instances capacity provider reaches ACTIVE or CREATE_FAILED",
        )
        if cp_desc["status"] == "ACTIVE":
            return cp_desc
        denied = "ServiceAccessDeniedException" in (cp_desc.get("updateStatusReason") or "")
        if not denied or time.monotonic() >= attempts_deadline:
            raise AssertionError(f"managed-instances capacity provider never reached ACTIVE: {cp_desc}")
        time.sleep(5)


def _register_daemon_task_definition(ctx, ecs, family=None):
    family = family or ctx.unique_name("sim2real-behav-ecs-daemontd-")
    resp = ecs.register_daemon_task_definition(family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS)
    arn = resp["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=arn))
    return ecs.describe_daemon_task_definition(daemonTaskDefinition=arn)["daemonTaskDefinition"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateDaemon calls to different revisions leave the daemon ACTIVE on exactly
    one of them."""
    ecs = ctx.client("ecs")
    cluster_name = "default"
    try:
        ecs.create_cluster(clusterName=cluster_name)  # idempotent; ensure "default" exists
    except Exception:
        pass

    # Positive control: plain ECS control-plane operations succeed for the caller,
    # so a denial below is a specific refusal of Managed Instances, not evidence that
    # credentials or the account are broadly broken.
    control_dtd = _register_daemon_task_definition(ctx, ecs)
    assert control_dtd["status"] == "ACTIVE", (
        f"expected a freshly registered daemon task definition to be ACTIVE, got {control_dtd}"
    )

    try:
        cp_desc = _create_managed_instances_capacity_provider(ctx, ecs, cluster_name)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"could not provision a Managed Instances capacity provider: {exc}") from None

    try:
        dtd1 = control_dtd
        daemon_name = ctx.unique_name("sim2real-behav-ecs-daemon-")
        try:
            created = ecs.create_daemon(
                daemonName=daemon_name,
                clusterArn=cluster_name,
                daemonTaskDefinitionArn=dtd1["daemonTaskDefinitionArn"],
                capacityProviderArns=[cp_desc["capacityProviderArn"]],
            )
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"CreateDaemon not usable in this account/region: {exc}") from None

        daemon_arn = created["daemonArn"]
        ctx.on_cleanup(lambda: ecs.delete_daemon(daemonArn=daemon_arn))
        assert created["status"] == "ACTIVE", f"expected ACTIVE on create, got {created['status']}"

        dtd2 = _register_daemon_task_definition(ctx, ecs, family=dtd1["family"] + "-v2")
        dtd3 = _register_daemon_task_definition(ctx, ecs, family=dtd1["family"] + "-v3")

        def _update_v2():
            return ecs.update_daemon(
                daemonArn=daemon_arn,
                daemonTaskDefinitionArn=dtd2["daemonTaskDefinitionArn"],
                capacityProviderArns=[cp_desc["capacityProviderArn"]],
            )

        def _update_v3():
            return ecs.update_daemon(
                daemonArn=daemon_arn,
                daemonTaskDefinitionArn=dtd3["daemonTaskDefinitionArn"],
                capacityProviderArns=[cp_desc["capacityProviderArn"]],
            )

        results = _run_concurrent([_update_v2, _update_v3], timeout_s=60)
        # AWS accepts both racing updates: each is ACTIVE with its own deployment, and the
        # last one applied becomes the daemon's deployment.
        timed_out = [i for i, r in enumerate(results) if isinstance(r, concurrent.futures.TimeoutError)]
        if timed_out:
            raise AssertionError(f"racer {timed_out} did not finish within the timeout ({results!r})")
        for r in results:
            if isinstance(r, BaseException) and not isinstance(r, ClientError):
                raise r
        refused = [r for r in results if isinstance(r, ClientError)]
        if refused:
            raise AssertionError(
                f"expected AWS to accept both concurrent UpdateDaemon calls, got "
                f"{_concurrent_error_codes(refused)} ({refused!r})"
            )
        for r in results:
            assert r["daemonArn"] == daemon_arn and r["status"] == "ACTIVE" and r.get("deploymentArn"), (
                f"expected each accepted UpdateDaemon to return the ACTIVE daemon and a deployment, got {r}"
            )
        assert results[0]["deploymentArn"] != results[1]["deploymentArn"], (
            f"expected each accepted update to start its own deployment, got {results}"
        )

        final = _poll_until(
            lambda: ecs.describe_daemon(daemonArn=daemon_arn)["daemon"],
            lambda d: d["status"] == "ACTIVE",
            timeout_s=40,
            interval_s=3,
            description="the daemon stays ACTIVE after the race resolves",
        )
        winners = [
            (r, dtd) for r, dtd in zip(results, (dtd2, dtd3), strict=True) if r["deploymentArn"] == final.get("deploymentArn")
        ]
        assert len(winners) == 1, (
            f"expected the daemon's deployment to be exactly one racer's deployment, got {final} vs {results}"
        )
        winner, winner_dtd = winners[0]
        assert final["updatedAt"] == winner["updatedAt"], (
            f"expected the daemon's updatedAt to be the winning update's, got {final} vs {winner}"
        )

        deployment = _poll_until(
            lambda: ecs.describe_daemon_deployments(daemonDeploymentArns=[winner["deploymentArn"]])[
                "daemonDeployments"
            ][0],
            lambda d: (d.get("targetDaemonRevision") or {}).get("arn") is not None,
            timeout_s=60,
            interval_s=3,
            description="the winning deployment names a target revision",
        )
        target_revision_arn = deployment["targetDaemonRevision"]["arn"]
        revision = ecs.describe_daemon_revisions(daemonRevisionArns=[target_revision_arn])[
            "daemonRevisions"
        ][0]
        assert revision["daemonTaskDefinitionArn"] == winner_dtd["daemonTaskDefinitionArn"], (
            f"expected the winning deployment to target the winner's task definition "
            f"{winner_dtd['daemonTaskDefinitionArn']}, got {revision['daemonTaskDefinitionArn']}"
        )
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(f"ECS Managed Daemons not exercisable in this account/region: {exc}") from None


def _delete_capacity_provider_if_present(ecs, name, cluster, timeout_s=300.0, interval_s=10.0):
    """Teardown: delete the cluster-scoped capacity provider and wait until it is gone, tolerating
    one already gone; retry while a just-deleted daemon still holds it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_capacity_provider(capacityProvider=name, cluster=cluster)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ClientException" and "does not exist" in err.get("Message", ""):
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while True:
        found = [cp for cp in ecs.describe_capacity_providers(cluster=cluster).get("capacityProviders", [])
                 if cp.get("name") == name]
        if not found or found[0].get("status") == "INACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity provider {name} still {found[0].get('status')!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
