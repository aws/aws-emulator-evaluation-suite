"""get-backlog-task-rejection-distinguishes-missing-space-from-missing-task."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-backlog-task-rejection-distinguishes-missing-space-from-missing-task"
GROUP = 'backlog'
SERVICES = ['devops-agent']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """GetBacklogTask tells a missing agent space (fail-closed AccessDenied) apart from a
    missing task in a real agent space (a specific ResourceNotFound).
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    control = client.get_agent_space(agentSpaceId=space_id)
    assert control["agentSpace"]["agentSpaceId"] == space_id, f"positive control failed: {control!r}"

    missing_task_id = ctx.unique_name("sim2real-behav-devops-agent-missing-task-")
    code, message = _error(lambda: client.get_backlog_task(agentSpaceId=space_id, taskId=missing_task_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Task not found: {missing_task_id}", f"unexpected message {message!r}"

    missing_space_id = ctx.unique_name("sim2real-behav-devops-agent-missing-space-")
    code, message = _error(lambda: client.get_backlog_task(agentSpaceId=missing_space_id, taskId=missing_task_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message!r}"
    assert message == "Access denied", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
