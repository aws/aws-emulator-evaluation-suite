"""send-command-zero-target-invocations."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-command-zero-target-invocations"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SendCommand against a tag target matching nothing yields zero invocations."""

    ssm = ctx.client("ssm")

    def _error(fn):
        """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message", "")
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

    def _call_with_retry(fn, retries=10, delay=3.0):
        last = None
        for _ in range(retries):
            try:
                return fn()
            except ClientError as exc:
                last = exc
                code = exc.response.get("Error", {}).get("Code")
                if code in ("TooManyUpdates", "ThrottlingException"):
                    time.sleep(delay)
                    continue
                raise
        raise last

    tag_key = "tag:" + ctx.unique_name("nomatch-")
    resp = _call_with_retry(
        lambda: ssm.send_command(
            DocumentName="AWS-RunShellScript",
            Targets=[{"Key": tag_key, "Values": [ctx.unique_name("val-")]}],
            Parameters={"commands": ["echo behavioral-probe"]},
        )
    )
    command = resp["Command"]
    command_id = command["CommandId"]
    assert command["DocumentName"] == "AWS-RunShellScript", command
    assert command["Status"] == "Pending", (
        f"SendCommand reports a just-sent command as Pending, got Status {command['Status']!r}"
    )
    assert command["TargetCount"] == 0, command

    listed = ssm.list_commands(CommandId=command_id)["Commands"]
    assert len(listed) == 1, listed
    assert listed[0]["CommandId"] == command_id, listed[0]

    invocations = ssm.list_command_invocations(CommandId=command_id)[
        "CommandInvocations"
    ]
    assert invocations == [], (
        f"a command with no matching targets must have no invocations: {invocations}"
    )

    # No invocation exists for an arbitrary instance under this command.
    code, message = _error(
        lambda: ssm.get_command_invocation(
            CommandId=command_id, InstanceId="i-0123456789abcdef0"
        )
    )
    assert code == "InvocationDoesNotExist", code
    assert message == f"Invocation not found for {command_id}, i-0123456789abcdef0", message

    # Positive control: CancelCommand accepts the real command id we just created —
    # without this, "rejects an unknown id" cannot be told apart from "rejects every
    # CancelCommand call".
    _call_with_retry(lambda: ssm.cancel_command(CommandId=command_id))

    # CancelCommand must reject an unknown (well-formed) command id.
    unknown_command_id = str(uuid.uuid4())
    cancel_code, cancel_message = _error(lambda: ssm.cancel_command(CommandId=unknown_command_id))
    assert cancel_code == "InvalidCommandId", cancel_code
    assert cancel_message == f"Command id {unknown_command_id} does not exist.", cancel_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
