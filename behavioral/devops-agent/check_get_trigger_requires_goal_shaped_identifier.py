"""get-trigger-requires-goal-shaped-identifier."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-trigger-requires-goal-shaped-identifier"
GROUP = 'triggers'
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
    """GetTrigger validates triggerId against the internal goal-id pattern before any lookup,
    reports a well-formed but unknown id as a missing Goal, and fails closed on a missing space.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    control = client.get_agent_space(agentSpaceId=space_id)
    assert control["agentSpace"]["agentSpaceId"] == space_id, f"positive control failed: {control!r}"

    code, message = _error(lambda: client.get_trigger(agentSpaceId=space_id, triggerId="not-a-trigger"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "1 validation error detected. Value at '/goalId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        "^goal-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ), f"unexpected message {message!r}"

    well_formed_missing = "goal-00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: client.get_trigger(agentSpaceId=space_id, triggerId=well_formed_missing))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Goal not found: {well_formed_missing}", f"unexpected message {message!r}"

    missing_space_id = ctx.unique_name("sim2real-behav-devops-agent-missing-space-")
    code, message = _error(lambda: client.get_trigger(agentSpaceId=missing_space_id, triggerId=well_formed_missing))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message!r}"
    assert message == "Access denied", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
