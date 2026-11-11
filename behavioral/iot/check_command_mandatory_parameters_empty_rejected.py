"""command-mandatory-parameters-empty-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "command-mandatory-parameters-empty-rejected"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCommand sent with an empty mandatoryParameters list (client validation off) fails
    with ValidationException and the exact length message and creates no command, while a
    well-formed command keeps its payload."""
    iot = ctx.client("iot")
    raw_iot = ctx.client("iot", config=Config(parameter_validation=False))

    bad_id = ctx.unique_name("sim2real-iot-cmdbad-")
    good_id = ctx.unique_name("sim2real-iot-cmdok-")

    err = _error(
        lambda: raw_iot.create_command(
            commandId=bad_id,
            namespace="AWS-IoT",
            payload={"content": b"static-payload", "contentType": "text/plain"},
            mandatoryParameters=[],
        )
    )
    assert err == ("ValidationException", (
        "1 validation error detected: Value '[]' at 'mandatoryParameters' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    )), err

    # effect absent: the rejected command was never created
    notfound = _error(lambda: iot.get_command(commandId=bad_id))
    assert notfound == ("ResourceNotFoundException", f"Command {bad_id} cannot be found."), notfound

    # positive control: a well-formed static command in the same file still succeeds
    iot.create_command(
        commandId=good_id,
        namespace="AWS-IoT",
        payload={"content": b"ok-payload", "contentType": "text/plain"},
    )
    ctx.on_cleanup(lambda: iot.delete_command(commandId=good_id))

    got = iot.get_command(commandId=good_id)
    assert got["payload"]["content"] == b"ok-payload"


def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
