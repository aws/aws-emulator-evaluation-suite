"""list-checks-invalid-pillar-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-checks-invalid-pillar-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["trustedadvisor"]

INVALID_PILLAR_MESSAGE = (
    "1 validation error detected: Value 'not_a_real_pillar' at 'pillar' failed to satisfy "
    "constraint: Member must satisfy enum value set: [security, service_limits, "
    "cost_optimizing, operational_excellence, fault_tolerance, performance]"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListChecks validates the pillar enum strictly: an out-of-enum value is rejected with
    ValidationException naming the value and the enum, while a valid pillar is not refused by
    that validation."""
    ta = ctx.client("trustedadvisor")

    bad_code, bad_msg = _error(lambda: ta.list_checks(pillar="not_a_real_pillar"))
    assert bad_code == "ValidationException", (
        f"expected ValidationException for an invalid pillar enum value, got {bad_code!r}: {bad_msg!r}"
    )
    assert bad_msg == INVALID_PILLAR_MESSAGE, (
        f"expected the exact enum-violation message {INVALID_PILLAR_MESSAGE!r}, got {bad_msg!r}"
    )

    # control: a valid pillar is not refused by the same validation, so the rejection above is
    # not a blanket refusal. The call may succeed or be refused for another reason; neither is
    # graded.
    control_code = _outcome(lambda: ta.list_checks(pillar="cost_optimizing", maxResults=10))
    assert control_code != bad_code, (
        "a valid pillar filter must not be rejected like the invalid-enum one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
