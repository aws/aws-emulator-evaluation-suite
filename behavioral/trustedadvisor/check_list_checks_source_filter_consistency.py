"""list-checks-source-filter-consistency."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-checks-source-filter-consistency"
GROUP = "list-filtering"
SERVICES = ["trustedadvisor"]

INVALID_SOURCE_MESSAGE = (
    "1 validation error detected: Value 'not_a_real_source' at 'source' failed to satisfy "
    "constraint: Member must satisfy enum value set: [rds, pse, well_architected, aws_config, "
    "manual, resilience_hub, stir, compute_optimizer, resilience, cost_explorer, "
    "cost_optimization_hub, ta_check, security_hub, lse]"
)


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded with {result!r}")


def _outcome(fn):
    """Call fn(); return its error code, or "(accepted)" when it succeeds."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return "(accepted)"


@tags("axis:rejection", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChecks rejects an out-of-enum source filter with ValidationException naming the
    enum, while the well-formed source=ta_check filter is not refused by that validation."""
    ta = ctx.client("trustedadvisor")

    bad_code, bad_msg = _error(lambda: ta.list_checks(source="not_a_real_source"))
    assert bad_code == "ValidationException", (
        f"expected ValidationException for an invalid source enum value, got {bad_code!r}"
    )
    assert bad_msg == INVALID_SOURCE_MESSAGE, (
        f"expected the exact enum-violation message {INVALID_SOURCE_MESSAGE!r}, got {bad_msg!r}"
    )

    # control: the well-formed source=ta_check filter is not refused by the same validation, so
    # the rejection above is not a blanket refusal. The call may succeed or be refused for
    # another reason; neither is graded.
    control_code = _outcome(lambda: ta.list_checks(source="ta_check", maxResults=200))
    assert control_code != bad_code, (
        "a well-formed source filter must not be rejected like the invalid-enum one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
