"""create-daemon-unknown-cluster-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-daemon-unknown-cluster-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDaemon on a nonexistent clusterArn fails with ClusterNotFoundException, while the
    identical call on a real cluster does not, so the rejection is about the missing cluster."""
    from botocore.exceptions import ClientError

    ecs = ctx.client("ecs")
    if not hasattr(ecs, "create_daemon"):
        raise AssertionError("installed botocore/boto3 has no ECS Managed Daemons operations")

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_cluster_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:cluster/{ctx.unique_name('sim2real-missing-cluster-')}"
    bogus_cp_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:capacity-provider/{ctx.unique_name('sim2real-missing-cp-')}"
    )

    real_cluster_name = ctx.unique_name("sim2real-daemon-cluster-")
    real_cluster_arn = ecs.create_cluster(
        clusterName=real_cluster_name,
        tags=[{"key": "sim2real-check", "value": "create-daemon-unknown-cluster-rejected"}],
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster_name))

    family = ctx.unique_name("sim2real-daemon-td-")
    td_arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "agent",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "memory": 128,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real-check", "value": "create-daemon-unknown-cluster-rejected"}],
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)))

    control_code = None
    try:
        control_resp = ecs.create_daemon(
            daemonName=ctx.unique_name("sim2real-daemon-control-"),
            clusterArn=real_cluster_arn,
            daemonTaskDefinitionArn=td_arn,
            capacityProviderArns=[bogus_cp_arn],
        )
    except ClientError as err:
        control_code = err.response["Error"]["Code"]
    else:
        control_arn = control_resp["daemonArn"]
        ctx.on_cleanup(lambda: _safe(lambda: ecs.delete_daemon(daemonArn=control_arn)))
        raise AssertionError(
            "CreateDaemon against a REAL cluster with a bogus capacity-provider ARN "
            "unexpectedly succeeded -- capacity providers are not validated"
        )

    assert control_code != "ClusterNotFoundException", (
        "positive control: CreateDaemon against a REAL cluster reported "
        f"ClusterNotFoundException (got {control_code!r} expected), so cluster existence "
        "cannot be isolated from capacity-provider validation on this account"
    )

    code = message = None
    try:
        ecs.create_daemon(
            daemonName=ctx.unique_name("sim2real-daemon-"),
            clusterArn=bogus_cluster_arn,
            daemonTaskDefinitionArn=td_arn,
            capacityProviderArns=[bogus_cp_arn],
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
    else:
        raise AssertionError("CreateDaemon against a nonexistent cluster unexpectedly succeeded")

    assert code == "ClusterNotFoundException", f"expected ClusterNotFoundException, got {code!r}"
    expected_message = "Cluster not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
_GONE_CODES = ("DaemonNotFoundException", "DaemonNotActiveException", "ClusterNotFoundException")


def _safe(fn) -> None:
    """Run a teardown delete: a resource already gone is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] not in _GONE_CODES and "does not exist" not in error.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
