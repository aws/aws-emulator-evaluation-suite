"""task-set-delete-primary-without-force-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "task-set-delete-primary-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTaskSet without force deletes a non-PRIMARY task set but fails with InvalidParameterException
    "Primary TaskSet cannot be deleted" on the PRIMARY set of an EXTERNAL-controller service, which stays
    PRIMARY; once another set is promoted it is ACTIVE and the same delete succeeds.
    """
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx)
    net_cfg = _default_network(ctx)
    task_def = _register_fargate_task_def(ctx, ctx.unique_name("sim2real-ecs-td-"))
    service_name = ctx.unique_name("sim2real-ecs-svc-")

    ecs.create_service(
        cluster=cluster["clusterArn"],
        serviceName=service_name,
        # EXTERNAL-controller services don't use desiredCount for scaling (task sets
        # own the scale), but real ECS still requires the parameter to be present.
        desiredCount=0,
        deploymentController={"type": "EXTERNAL"},
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(cluster=cluster["clusterArn"], service=service_name, force=True)
    )

    def _create_task_set():
        ts = ecs.create_task_set(
            cluster=cluster["clusterArn"],
            service=service_name,
            taskDefinition=task_def["taskDefinitionArn"],
            launchType="FARGATE",
            # scale=0 keeps this a pure control-plane exercise: no Fargate task ever
            # needs to actually launch to exercise the PRIMARY-delete rejection.
            scale={"value": 0.0, "unit": "PERCENT"},
            networkConfiguration=net_cfg,
        )["taskSet"]
        ctx.on_cleanup(
            lambda tid=ts["id"]: _delete_task_set_best_effort(
                ecs, cluster["clusterArn"], service_name, tid
            )
        )
        return ts

    ts_a = _create_task_set()
    ts_b = _create_task_set()
    ts_c = _create_task_set()

    promoted = ecs.update_service_primary_task_set(
        cluster=cluster["clusterArn"], service=service_name, primaryTaskSet=ts_a["taskSetArn"]
    )["taskSet"]
    assert promoted["status"] == "PRIMARY", f"expected PRIMARY, got {promoted['status']}"

    # Positive control: the identical call (DeleteTaskSet, no force) succeeds against a
    # task set that is NOT primary. Without this, "rejects deleting the primary task
    # set" is indistinguishable from "rejects every DeleteTaskSet without force".
    ecs.delete_task_set(cluster=cluster["clusterArn"], service=service_name, taskSet=ts_b["id"])
    _assert_gone(ecs, cluster["clusterArn"], service_name, ts_b["id"])

    # Break: the same call against the now-PRIMARY task set is rejected.
    error = _error(
        lambda: ecs.delete_task_set(cluster=cluster["clusterArn"], service=service_name, taskSet=ts_a["id"])
    )
    expected = ("InvalidParameterException", "Primary TaskSet cannot be deleted")
    assert error == expected, f"expected {expected!r}, got {error!r}"

    still_there = ecs.describe_task_sets(
        cluster=cluster["clusterArn"], service=service_name, taskSets=[ts_a["taskSetArn"]]
    )["taskSets"]
    assert len(still_there) == 1 and still_there[0]["status"] == "PRIMARY", (
        f"expected the rejected delete to leave ts_a in place as PRIMARY, got {still_there}"
    )

    # Restore: promoting a different task set demotes ts_a back to ACTIVE.
    ecs.update_service_primary_task_set(
        cluster=cluster["clusterArn"], service=service_name, primaryTaskSet=ts_c["taskSetArn"]
    )
    demoted = _poll_until(
        lambda: ecs.describe_task_sets(
            cluster=cluster["clusterArn"], service=service_name, taskSets=[ts_a["taskSetArn"]]
        )["taskSets"][0],
        lambda s: s["status"] != "PRIMARY",
        timeout_s=30.0,
    )
    assert demoted["status"] == "ACTIVE", f"expected ts_a demoted to ACTIVE, got {demoted['status']}"

    # The identical call now succeeds against the same task set, once it is no longer PRIMARY.
    ecs.delete_task_set(cluster=cluster["clusterArn"], service=service_name, taskSet=ts_a["id"])
    _assert_gone(ecs, cluster["clusterArn"], service_name, ts_a["id"])


import time

from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected the call to raise a ClientError, it succeeded")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _assert_gone(ecs, cluster_arn, service_name, ts_id, *, timeout_s=60.0, interval_s=3.0):
    # DeleteTaskSet's removal isn't synchronous on real AWS -- describe_task_sets can
    # still momentarily echo the just-deleted id while it drains, so poll with a bound
    # instead of asserting on the very next call.
    def _remaining():
        return [
            t["id"]
            for t in ecs.describe_task_sets(
                cluster=cluster_arn, service=service_name, taskSets=[ts_id]
            )["taskSets"]
        ]

    remaining = _poll_until(
        _remaining, lambda ids: ts_id not in ids, timeout_s=timeout_s, interval_s=interval_s
    )
    assert ts_id not in remaining, f"expected {ts_id} gone after DeleteTaskSet, still present: {remaining}"


def _delete_task_set_best_effort(ecs, cluster_arn, service_name, ts_id):
    try:
        ecs.delete_task_set(cluster=cluster_arn, service=service_name, taskSet=ts_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "ServiceNotFoundException",
            "TaskSetNotFoundException",
        ):
            raise


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    # Real ECS rejects CreateTaskSet on an awsvpc task definition without a
    # networkConfiguration even at scale=0, so a real subnet/security group is still
    # required -- but since scale=0 never actually places a Fargate task (no ENI is
    # ever attached), the account's ordinary shared network is sufficient here.
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
        "Subnets", []
    )
    if not subnets:
        raise AssertionError("no shared network VPC subnet available for FARGATE networking")
    vpc_id = subnets[0]["VpcId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    ).get("SecurityGroups", [])
    if not sgs:
        raise AssertionError("no default security group available in the shared network")
    return {
        "awsvpcConfiguration": {
            "subnets": [subnets[0]["SubnetId"]],
            "securityGroups": [sgs[0]["GroupId"]],
        }
    }


def _create_cluster(ctx):
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name)["cluster"]

    def _cleanup(arn=cluster["clusterArn"]):
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return cluster


def _register_fargate_task_def(ctx, family, command=None):
    ecs = ctx.client("ecs")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": command or ["sleep", "600"],
            }
        ],
    )
    td = resp["taskDefinition"]

    def _cleanup(arn=td["taskDefinitionArn"]):
        try:
            ecs.deregister_task_definition(taskDefinition=arn)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and any(f in err.get("Message", "") for f in ("Unable to describe task definition", "in the process of being deleted"))
            ):
                raise
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup)
    return td


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
