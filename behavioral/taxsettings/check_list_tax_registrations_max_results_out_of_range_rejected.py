"""list-tax-registrations-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tax-registrations-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTaxRegistrations refuses maxResults 1001, above the declared [1, 1000], with ValidationException and its
    exact message; maxResults 5 is not refused with ValidationException and returns at most 5 accountDetails."""
    ts = ctx.client("taxsettings")

    error = _client_error(lambda: ts.list_tax_registrations(maxResults=1001))
    code = error.get("Code")
    assert code == "ValidationException", (
        f"expected ValidationException for maxResults=1001 (range is [1, 1000]), got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"

    try:
        resp = ts.list_tax_registrations(maxResults=5)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] != "ValidationException", (
            "maxResults=5 is in-bounds; expected no ValidationException, got "
            f"{err['Code']!r}: {err.get('Message')!r}"
        )
    else:
        account_details = resp["accountDetails"]
        assert len(account_details) <= 5, (
            f"expected at most 5 accountDetails for maxResults=5, got {len(account_details)}"
        )


def _client_error(fn):
    """An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected list_tax_registrations(maxResults=1001) to be rejected as out-of-range, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
