"""list-supplemental-tax-registrations-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-supplemental-tax-registrations-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSupplementalTaxRegistrations sent unvalidated refuses maxResults 1001 and 0, outside the declared
    [1, 1000], each with ValidationException and its exact message, and lists with maxResults 5."""
    ts = ctx.client("taxsettings", config=Config(parameter_validation=False))

    code, message = _error(lambda: ts.list_supplemental_tax_registrations(maxResults=1001))
    assert code == "ValidationException", (
        f"expected ValidationException for maxResults over the ceiling, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code2, message2 = _error(lambda: ts.list_supplemental_tax_registrations(maxResults=0))
    assert code2 == "ValidationException", (
        f"expected ValidationException for maxResults below the floor, got {code2!r}"
    )
    expected2 = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Positive control: an in-range value is accepted (never rejected on
    # cardinality grounds), regardless of how many registrations exist.
    resp = ts.list_supplemental_tax_registrations(maxResults=5)
    assert isinstance(resp["taxRegistrations"], list), (
        f"expected taxRegistrations to be a list, got {resp.get('taxRegistrations')!r}"
    )


def _error(fn):
    """The rejected call's (code, message); an unexpected success raises, so an emulator that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


