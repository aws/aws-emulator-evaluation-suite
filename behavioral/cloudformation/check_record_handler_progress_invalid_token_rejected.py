"""record-handler-progress-invalid-token-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "record-handler-progress-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordHandlerProgress with a BearerToken never issued for an in-flight operation fails with
    ValidationError "BearerToken '<token>' is invalid", not InvalidStateTransition or
    OperationStatusCheckFailedException."""
    cfn = ctx.client("cloudformation")
    bogus_token = str(uuid.uuid4())

    error = _error(
        lambda: cfn.record_handler_progress(BearerToken=bogus_token, OperationStatus="SUCCESS")
    )
    code = error["Code"]
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    message = error.get("Message")
    # The message echoes this run's own bearer token, proving the target inspected it
    # rather than returning a canned error.
    expected = f"BearerToken '{bogus_token}' is invalid"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the Error dict of the ClientError it raises; raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
