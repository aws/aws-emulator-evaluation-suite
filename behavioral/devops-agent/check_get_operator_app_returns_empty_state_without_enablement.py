"""get-operator-app-returns-empty-state-without-enablement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-operator-app-returns-empty-state-without-enablement"
GROUP = 'operator-app'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOperatorApp succeeds with an empty state on a space that never enabled one, and
    reports a missing agent space by name and account rather than treating it like a missing app.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    default_state = client.get_operator_app(agentSpaceId=space_id)
    default_state.pop("ResponseMetadata", None)
    assert default_state == {}, f"expected an empty default operator app state, got {default_state!r}"

    missing_space_id = ctx.unique_name("sim2real-behav-devops-agent-missing-space-")
    code, message = _error(lambda: client.get_operator_app(agentSpaceId=missing_space_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == (
        f'Could not find Agent Space with provided agentSpaceId "{missing_space_id}" '
        f'in accountId "{ctx.account}"'
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
