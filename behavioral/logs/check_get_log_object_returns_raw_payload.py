"""get-log-object-returns-raw-payload."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-log-object-returns-raw-payload"
GROUP = "state-machine"
SERVICES = ["logs"]


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogObject with an arbitrary string as logObjectPointer raises InvalidParameterException with its
    exact message instead of returning data.
    """

    logs = ctx.client("logs")
    bogus_pointer = f"sim2real-nonexistent-log-object-{uuid.uuid4().hex}"

    code, message = _error(lambda: logs.get_log_object(logObjectPointer=bogus_pointer))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a non-existent/malformed logObjectPointer, "
        f"got {code}"
    )
    expected_message = "Invalid log object pointer format."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
