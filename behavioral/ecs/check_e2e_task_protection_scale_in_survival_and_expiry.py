"""e2e-task-protection-scale-in-survival-and-expiry."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-task-protection-scale-in-survival-and-expiry"
GROUP = "e2e"
SERVICES = ["ecs"]


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateTaskProtection.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A scale-in-protected task survives a scale-in that stops its unprotected sibling and is
    removable once protection expires; an out-of-range expiresInMinutes (max 2880) is rejected
    with InvalidParameterException and never applied."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _default_network(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])

    def _teardown_cluster():
        # DeleteService only starts the async drain; DeleteCluster rejects with
        # ClusterContainsServicesException / ClusterContainsTasksException until the service
        # and its tasks have gone, so retry across the drain within a bound.
        deadline = time.monotonic() + 240
        while True:
            try:
                ecs.delete_cluster(cluster=cluster_name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsServicesException",
                    "ClusterContainsTasksException",
                ) or time.monotonic() >= deadline:
                    raise
                time.sleep(5)

    ctx.on_cleanup(_teardown_cluster)

    family = ctx.unique_name("sim2real-ecs-taskdef-")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "main",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn])))
    ctx.on_cleanup(lambda: _safe(lambda: ecs.deregister_task_definition(taskDefinition=td_arn)))

    service_name = ctx.unique_name("sim2real-ecs-svc-")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    _ensure_service_linked_role(ctx)
    _create_service_with_retry(
        ecs,
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=2,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))
    )

    task_arns = _poll_task_arns(ctx, cluster_name, service_name, expected=2, timeout_s=240)
    protected_task, other_task = task_arns[0], task_arns[1]

    # Break exactly one thing first: an out-of-range expiresInMinutes (max is
    # 2880) must be rejected and must not silently apply protection.
    bad_error = _error(
        lambda: ecs.update_task_protection(
            cluster=cluster_name, tasks=[protected_task], protectionEnabled=True, expiresInMinutes=5000
        )
    )
    assert bad_error == ("InvalidParameterException", "expiresInMinutes must be at most 2880"), bad_error
    pre_check = ecs.get_task_protection(cluster=cluster_name, tasks=[protected_task])
    assert not pre_check.get("failures"), pre_check.get("failures")
    pre_protected = pre_check["protectedTasks"]
    assert pre_protected[0]["protectionEnabled"] is False, (
        f"rejected expiresInMinutes=5000 must not have applied protection, got {pre_protected}"
    )

    # Enable protection with the minimum allowed duration (1 minute) so the
    # expiry half of the check does not need to wait a long window.
    protect_resp = ecs.update_task_protection(
        cluster=cluster_name, tasks=[protected_task], protectionEnabled=True, expiresInMinutes=1
    )
    assert protect_resp["protectedTasks"][0]["protectionEnabled"] is True, protect_resp

    gtp = ecs.get_task_protection(cluster=cluster_name, tasks=[protected_task])
    assert gtp["protectedTasks"][0]["protectionEnabled"] is True, gtp

    # Scale in by one: ECS must not stop the protected task.
    ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=1)
    _poll_running_count(ctx, cluster_name, service_name, 1, timeout_s=240)

    surviving = ecs.describe_tasks(cluster=cluster_name, tasks=[protected_task])["tasks"][0]
    assert surviving["lastStatus"] == "RUNNING", (
        f"protected task must survive scale-in, got {surviving['lastStatus']}"
    )
    stopped = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[other_task])["tasks"][0]["lastStatus"],
        lambda status: status == "STOPPED",
        timeout_s=180,
        interval_s=5,
    )
    assert stopped == "STOPPED", stopped

    # Wait for the 1-minute protection window to lapse and reset automatically.
    _poll_until(
        lambda: ecs.get_task_protection(cluster=cluster_name, tasks=[protected_task])["protectedTasks"][0][
            "protectionEnabled"
        ],
        lambda enabled: enabled is False,
        timeout_s=180,
        interval_s=10,
    )

    # Now that protection has expired, a further scale-in to zero must remove it too.
    ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=0)
    _poll_running_count(ctx, cluster_name, service_name, 0, timeout_s=240)
    final_status = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_name, tasks=[protected_task])["tasks"][0]["lastStatus"],
        lambda status: status == "STOPPED",
        timeout_s=120,
        interval_s=5,
    )
    assert final_status == "STOPPED", (
        f"protected task must be removable once protection has expired, got {final_status}"
    )


# ===== helpers =====
def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "ServiceNotFoundException")
            and not (err["Code"] == "ClientException" and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted")))
        ):
            raise


def _ensure_service_linked_role(ctx):
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_service_with_retry(ecs, timeout_s=90.0, interval_s=10.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ecs.create_service(**kwargs)
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "InvalidParameterException" and "service linked role" in msg:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_running_count(ctx, cluster_name, service_name, expected, timeout_s):
    ecs = ctx.client("ecs")

    def probe():
        return ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]["runningCount"]

    value = _poll_until(probe, lambda count: count == expected, timeout_s=timeout_s, interval_s=8)
    assert value == expected, f"expected runningCount={expected}, got {value}"


def _poll_task_arns(ctx, cluster_name, service_name, expected, timeout_s):
    ecs = ctx.client("ecs")

    def probe():
        arns = ecs.list_tasks(cluster=cluster_name, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]
        if len(arns) != expected:
            return []
        tasks = ecs.describe_tasks(cluster=cluster_name, tasks=arns)["tasks"]
        if not all(t["lastStatus"] == "RUNNING" for t in tasks):
            return []
        return arns

    arns = _poll_until(probe, lambda arns: len(arns) == expected, timeout_s=timeout_s, interval_s=8)
    return sorted(arns)


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for awsvpc networking")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group available")
    sg_id = sgs[0]["GroupId"]
    return subnet_id, sg_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
