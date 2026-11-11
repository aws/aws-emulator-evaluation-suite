"""list-command-executions-for-sandbox-absent-not-found."""
from __future__ import annotations
import uuid

from behavioral_harness import tags

CHECK = "list-command-executions-for-sandbox-absent-not-found"
GROUP = "error-semantics"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A malformed sandboxId is refused with InvalidInputException, while a well-shaped id of an absent
    sandbox lists no command executions and BatchGetCommandExecutions reports the id in
    commandExecutionsNotFound: the List call filters, it does not look up."""
    codebuild = ctx.client("codebuild")

    malformed_id = ctx.unique_name("sim2real-behav-malformed-sandbox-")
    malformed_code, malformed_message = _client_error(
        lambda: codebuild.list_command_executions_for_sandbox(sandboxId=malformed_id)
    )
    assert malformed_code == "InvalidInputException", f"expected InvalidInputException, got {malformed_code}"
    assert malformed_message == "Invalid sandbox ID provided", malformed_message

    well_formed_missing_id = (
        f"{ctx.unique_name('sim2real-behav-nonexistent-proj')}:{uuid.uuid4()}"
    )
    resp = codebuild.list_command_executions_for_sandbox(sandboxId=well_formed_missing_id)
    assert resp.get("commandExecutions", []) == [], (
        f"expected an empty commandExecutions list for a nonexistent sandbox, got {resp.get('commandExecutions')}"
    )

    missing_cmd_exec_id = str(uuid.uuid4())
    batch_resp = codebuild.batch_get_command_executions(
        sandboxId=well_formed_missing_id, commandExecutionIds=[missing_cmd_exec_id]
    )
    assert batch_resp.get("commandExecutions", []) == [], (
        f"expected no commandExecutions for a nonexistent id, got {batch_resp.get('commandExecutions')}"
    )
    assert batch_resp["commandExecutionsNotFound"] == [missing_cmd_exec_id], (
        f"expected commandExecutionsNotFound == [{missing_cmd_exec_id}], "
        f"got {batch_resp['commandExecutionsNotFound']}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
