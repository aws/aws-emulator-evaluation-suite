"""daemon-deployment-timeout-marks-failed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "daemon-deployment-timeout-marks-failed"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDaemon with the built-in FARGATE capacity provider is rejected with
    InvalidParameterException (daemons need MANAGED_INSTANCES capacity providers), and no daemon
    appears in ListDaemons for the cluster.
    """
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_arn))

    family = ctx.unique_name("sim2real-behav-dtd-")
    daemon_td_arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/docker/library/alpine:3.20", "memory": 64, "essential": True}
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=daemon_td_arn))

    fargate_cp = ecs.describe_capacity_providers(capacityProviders=["FARGATE"])["capacityProviders"]
    assert fargate_cp, "expected the account-wide built-in FARGATE capacity provider to be describable"
    fargate_cp_arn = fargate_cp[0]["capacityProviderArn"]

    code, message = _error(
        lambda: ecs.create_daemon(
            clusterArn=cluster_arn,
            daemonName=ctx.unique_name("sim2real-behav-daemon-"),
            daemonTaskDefinitionArn=daemon_td_arn,
            capacityProviderArns=[fargate_cp_arn],
        )
    )

    assert code == "InvalidParameterException", (
        "expected CreateDaemon to reject a non-Managed-Instances capacity provider "
        f"(FARGATE) with InvalidParameterException, got code={code!r}"
    )
    assert message == 'All capacity providers must be of MANAGED_INSTANCES type for Daemon services', (
        f"expected the exact non-Managed-Instances capacity provider message, got {message!r}"
    )

    daemons = ecs.list_daemons(clusterArn=cluster_arn)["daemonSummariesList"]
    assert daemons == [], (
        f"expected no daemon to exist in {cluster_name} after CreateDaemon was rejected, "
        f"got {daemons!r}"
    )


# ===== helpers =====
def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_cluster(ctx, cluster_arn: str) -> None:
    """Delete the cluster, retrying while ECS still releases what it contains; a gone cluster is done."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            busy = code.startswith("ClusterContains") or code == "UpdateInProgressException"
            if not busy or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
