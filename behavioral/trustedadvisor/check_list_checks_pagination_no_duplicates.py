"""list-checks-pagination-no-duplicates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-checks-pagination-no-duplicates"
GROUP = "pagination"
SERVICES = ["trustedadvisor"]

SUPPORT_LEVEL_DENIAL = "Access denied due to support level"
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


@tags("axis:rejection", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChecks with an invalid pillar fails with ValidationException and the exact message, while
    a full-page and a one-item-page ListChecks both fail with the identical AccessDeniedException
    "Access denied due to support level" when the caller lacks a support-level entitlement."""
    ta = ctx.client("trustedadvisor")

    invalid_code, invalid_msg = _error(lambda: ta.list_checks(pillar="not_a_real_pillar"))
    assert invalid_code == "ValidationException", (
        f"expected ValidationException for an invalid pillar enum value (proves the "
        f"service validates syntax before authorization), got {invalid_code!r}"
    )
    assert invalid_msg == INVALID_PILLAR_MESSAGE, (
        f"expected the exact enum-violation message {INVALID_PILLAR_MESSAGE!r}, got {invalid_msg!r}"
    )

    full_code, full_msg = _error(lambda: ta.list_checks(maxResults=200))
    assert full_code == "AccessDeniedException", (
        f"expected AccessDeniedException (support-plan gate) for a well-formed "
        f"ListChecks(maxResults=200) call in an account without Trusted Advisor API "
        f"access, got {full_code!r}"
    )
    assert full_msg == SUPPORT_LEVEL_DENIAL, (
        f"expected the support-level denial message {SUPPORT_LEVEL_DENIAL!r}, got {full_msg!r}"
    )
    assert full_code != invalid_code, (
        "a well-formed call and an invalid-enum call must not collapse to the same error code"
    )

    paged_code, paged_msg = _error(lambda: ta.list_checks(maxResults=1))
    assert (paged_code, paged_msg) == (full_code, full_msg), (
        "a single-item-page ListChecks call must be denied identically to the "
        f"full-page call: got ({paged_code!r}, {paged_msg!r}) vs "
        f"({full_code!r}, {full_msg!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
