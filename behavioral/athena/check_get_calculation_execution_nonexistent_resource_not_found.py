"""get-calculation-execution-nonexistent-resource-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-calculation-execution-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]

# Real Athena answers an unresolvable calculation execution id with this exact text.
_NOT_AUTHORIZED = "Not authorized to make this request."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCalculationExecution, GetCalculationExecutionStatus and GetCalculationExecutionCode each
    fail InvalidRequestException for an unknown calculation execution id."""
    athena = ctx.client("athena")
    fake_calc_id = str(uuid.uuid4())

    code, message = _error(lambda: athena.get_calculation_execution(CalculationExecutionId=fake_calc_id))
    assert code == "InvalidRequestException", (
        f"GetCalculationExecution: expected InvalidRequestException, got {code}"
    )
    assert message == _NOT_AUTHORIZED, f"GetCalculationExecution: expected {_NOT_AUTHORIZED!r}, got {message!r}"

    code, message = _error(
        lambda: athena.get_calculation_execution_status(CalculationExecutionId=fake_calc_id)
    )
    assert code == "InvalidRequestException", (
        f"GetCalculationExecutionStatus: expected InvalidRequestException, got {code}"
    )
    assert message == _NOT_AUTHORIZED, (
        f"GetCalculationExecutionStatus: expected {_NOT_AUTHORIZED!r}, got {message!r}"
    )

    code, message = _error(
        lambda: athena.get_calculation_execution_code(CalculationExecutionId=fake_calc_id)
    )
    assert code == "InvalidRequestException", (
        f"GetCalculationExecutionCode: expected InvalidRequestException, got {code}"
    )
    assert message == _NOT_AUTHORIZED, (
        f"GetCalculationExecutionCode: expected {_NOT_AUTHORIZED!r}, got {message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
