"""exec-protection-agent-ops-on-missing-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "exec-protection-agent-ops-on-missing-cluster-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Exec, task-protection and agent state-change operations on a nonexistent cluster are rejected
    with ClusterNotFoundException (Submit* APIs: ClientException "Cluster not found."), while the
    same call on a real cluster fails only on the missing task, container instance or attachment."""
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    real_cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=real_cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=real_cluster_name))

    bogus_cluster = ctx.unique_name("no-such-cluster-")

    def _arns_for(cluster_name):
        task_arn = (
            f"arn:aws:ecs:{ctx.region}:{account_id}:task/{cluster_name}/"
            "00000000000000000000000000000000"
        )
        ci_arn = (
            f"arn:aws:ecs:{ctx.region}:{account_id}:container-instance/{cluster_name}/"
            "00000000000000000000000000000000"
        )
        return task_arn, ci_arn

    real_task_arn, real_ci_arn = _arns_for(real_cluster_name)
    fake_task_arn, fake_ci_arn = _arns_for(bogus_cluster)
    fake_attachment_arn = (
        f"arn:aws:ecs:{ctx.region}:{account_id}:attachment/00000000-0000-0000-0000-000000000000"
    )

    # --- ExecuteCommand ---
    code, message = _error(
        lambda: ecs.execute_command(
            cluster=real_cluster_name, task=real_task_arn, command="ls", interactive=True
        )
    )
    assert code == "InvalidParameterException", f"ExecuteCommand control: got {code}"
    assert message == "The specified task was not found. Specify a valid task ID and try again.", f"ExecuteCommand control: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.execute_command(
            cluster=bogus_cluster, task=fake_task_arn, command="ls", interactive=True
        )
    )
    assert code == "ClusterNotFoundException", f"ExecuteCommand: got {code}"
    assert message == "Cluster not found.", f"ExecuteCommand: unexpected message {message!r}"

    # --- GetTaskProtection --- (a real cluster answers 200 with the task MISSING,
    # never raises ClusterNotFoundException)
    control_failures = ecs.get_task_protection(cluster=real_cluster_name, tasks=[real_task_arn])[
        "failures"
    ]
    assert len(control_failures) == 1, f"GetTaskProtection control: got {control_failures}"
    assert control_failures[0]["reason"] == "MISSING", (
        f"GetTaskProtection control: got {control_failures[0]}"
    )

    code, message = _error(lambda: ecs.get_task_protection(cluster=bogus_cluster, tasks=[fake_task_arn]))
    assert code == "ClusterNotFoundException", f"GetTaskProtection: got {code}"
    assert message == "Cluster not found.", f"GetTaskProtection: unexpected message {message!r}"

    # --- UpdateTaskProtection --- (same shape: 200, task MISSING)
    control_failures = ecs.update_task_protection(
        cluster=real_cluster_name, tasks=[real_task_arn], protectionEnabled=True
    )["failures"]
    assert len(control_failures) == 1, f"UpdateTaskProtection control: got {control_failures}"
    assert control_failures[0]["reason"] == "MISSING", (
        f"UpdateTaskProtection control: got {control_failures[0]}"
    )

    code, message = _error(
        lambda: ecs.update_task_protection(
            cluster=bogus_cluster, tasks=[fake_task_arn], protectionEnabled=True
        )
    )
    assert code == "ClusterNotFoundException", f"UpdateTaskProtection: got {code}"
    assert message == "Cluster not found.", f"UpdateTaskProtection: unexpected message {message!r}"

    # --- UpdateContainerAgent ---
    code, message = _error(
        lambda: ecs.update_container_agent(cluster=real_cluster_name, containerInstance=real_ci_arn)
    )
    assert code == "ClientException", f"UpdateContainerAgent control: got {code}"
    assert message == f"Referenced container instance {real_ci_arn.rsplit('/', 1)[-1]} not found.", f"UpdateContainerAgent control: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.update_container_agent(cluster=bogus_cluster, containerInstance=fake_ci_arn)
    )
    assert code == "ClusterNotFoundException", f"UpdateContainerAgent: got {code}"
    assert message == "Cluster not found.", f"UpdateContainerAgent: unexpected message {message!r}"

    # --- SubmitAttachmentStateChanges ---
    code, message = _error(
        lambda: ecs.submit_attachment_state_changes(
            cluster=real_cluster_name,
            attachments=[{"attachmentArn": fake_attachment_arn, "status": "ATTACHED"}],
        )
    )
    assert code == "InvalidParameterException", f"SubmitAttachmentStateChanges control: got {code}"
    assert message == f"Attachment with id {fake_attachment_arn.rsplit('/', 1)[-1]} does not exist", f"SubmitAttachmentStateChanges control: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.submit_attachment_state_changes(
            cluster=bogus_cluster,
            attachments=[{"attachmentArn": fake_attachment_arn, "status": "ATTACHED"}],
        )
    )
    assert code == "ClientException", f"SubmitAttachmentStateChanges: got {code}"
    assert message == "Cluster not found.", f"SubmitAttachmentStateChanges: unexpected message {message!r}"

    # --- SubmitContainerStateChange ---
    code, message = _error(
        lambda: ecs.submit_container_state_change(
            cluster=real_cluster_name, task=real_task_arn, containerName="app", status="RUNNING"
        )
    )
    assert code == "InvalidParameterException", f"SubmitContainerStateChange control: got {code}"
    assert message == "The referenced task was not found", f"SubmitContainerStateChange control: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.submit_container_state_change(
            cluster=bogus_cluster, task=fake_task_arn, containerName="app", status="RUNNING"
        )
    )
    assert code == "ClientException", f"SubmitContainerStateChange: got {code}"
    assert message == "Cluster not found.", f"SubmitContainerStateChange: unexpected message {message!r}"

    # --- SubmitTaskStateChange ---
    code, message = _error(
        lambda: ecs.submit_task_state_change(
            cluster=real_cluster_name, task=real_task_arn, status="RUNNING"
        )
    )
    assert code == "InvalidParameterException", f"SubmitTaskStateChange control: got {code}"
    assert message == "The referenced task was not found", f"SubmitTaskStateChange control: unexpected message {message!r}"

    code, message = _error(
        lambda: ecs.submit_task_state_change(cluster=bogus_cluster, task=fake_task_arn, status="RUNNING")
    )
    assert code == "ClientException", f"SubmitTaskStateChange: got {code}"
    assert message == "Cluster not found.", f"SubmitTaskStateChange: unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
