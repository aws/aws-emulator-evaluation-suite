"""get-investigation-malformed-id-pattern-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-investigation-malformed-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """GetInvestigation rejects a 21-char InvestigationId that contains a non-digit; the
    same shape but all-digit id is a normal (not-found, but well-formed) request."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    # Exactly 21 characters (satisfies the SDK's length check) but not all-digits, so the
    # rejection is a genuine server-side pattern validation, not client-side length validation.
    malformed_id = "1" * 20 + "X"
    assert len(malformed_id) == 21 and not malformed_id.isdigit()

    code, message = _error(lambda: d.get_investigation(GraphArn=arn, InvestigationId=malformed_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{malformed_id}' at 'investigationId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: ^[0-9]+$"
    ), f"unexpected message: {message!r}"

    # positive control: a well-formed (all-digit, 21-char) id in the same shape is accepted
    # for processing and correctly reported as not found rather than rejected as malformed.
    well_formed_but_unknown_id = "1" * 21
    control_code, control_message = _error(
        lambda: d.get_investigation(GraphArn=arn, InvestigationId=well_formed_but_unknown_id)
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the well-formed control id, got {control_code!r}"
    )
    assert control_message == "The specified investigation does not exist", (
        f"unexpected message: {control_message!r}"
    )


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
