"""invalid-state-transition-record-handler-progress."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-state-transition-record-handler-progress"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RecordHandlerProgress with an unissued BearerToken fails ValidationError "BearerToken '<t>'
    is invalid", identically for a legal and an illegal transition: the token is checked first.
    """
    cfn = ctx.client("cloudformation")

    # Positive control: this account/credential pair is otherwise healthy for
    # CloudFormation, so the rejections below are specific to the bogus token
    # rather than a broken client or a denied caller.
    stacks = cfn.list_stacks()
    assert "StackSummaries" in stacks, f"expected a ListStacks response, got {stacks!r}"

    bogus_token = str(uuid.uuid4())
    # A genuine BearerToken is only minted by a live extension handler invocation, so the
    # legal/illegal pairing is what shows the state-transition check is never reached.

    illegal_error = _client_error(
        lambda: cfn.record_handler_progress(
            BearerToken=bogus_token,
            OperationStatus="IN_PROGRESS",
            CurrentOperationStatus="SUCCESS",
        )
    )
    assert illegal_error.get("Code") == "ValidationError", (
        f"RecordHandlerProgress reporting an illegal SUCCESS->IN_PROGRESS transition "
        f"against a BearerToken that was never issued: expected "
        f"ValidationError, got {illegal_error!r}"
    )
    expected_message = f"BearerToken '{bogus_token}' is invalid"
    assert illegal_error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {illegal_error!r}"
    )

    legal_error = _client_error(
        lambda: cfn.record_handler_progress(
            BearerToken=bogus_token,
            OperationStatus="SUCCESS",
            CurrentOperationStatus="IN_PROGRESS",
        )
    )
    assert legal_error == illegal_error, (
        f"the same unissued BearerToken must be rejected identically regardless of "
        f"whether the reported transition is itself legal (IN_PROGRESS->SUCCESS) or "
        f"illegal (SUCCESS->IN_PROGRESS) -- the state-transition check is unreachable "
        f"once token lookup fails; got illegal={illegal_error!r} legal={legal_error!r}"
    )
    assert legal_error.get("Code") == "ValidationError", f"expected ValidationError, got {legal_error!r}"
    assert legal_error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {legal_error!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"expected RecordHandlerProgress to reject the unissued BearerToken, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
