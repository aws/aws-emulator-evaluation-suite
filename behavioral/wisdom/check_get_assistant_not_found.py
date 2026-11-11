"""get-assistant-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-assistant-not-found"
GROUP = "error-semantics"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAssistant on a well-formed but never-created assistantId returns
    ResourceNotFoundException, while the identical call against a real assistant
    (positive control) succeeds."""
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(name=ctx.unique_name("sim2real-behav-asst-"), type="AGENT")["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    # positive control: the real assistant is reachable through the identical call
    got = wisdom.get_assistant(assistantId=assistant_id)["assistant"]
    assert got["assistantId"] == assistant_id, (
        f"expected GetAssistant to return {assistant_id}, got {got['assistantId']}"
    )

    bogus_id = str(uuid.uuid4())
    assert bogus_id != assistant_id
    code, message = _error(lambda: wisdom.get_assistant(assistantId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Assistant does not exist.", f"expected the assistant not-found message, got {message!r}"


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
