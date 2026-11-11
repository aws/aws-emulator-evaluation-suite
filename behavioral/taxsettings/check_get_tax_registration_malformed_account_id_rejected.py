"""get-tax-registration-malformed-account-id-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-tax-registration-malformed-account-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTaxRegistration sent unvalidated with the 5-digit accountId "12345" is refused with ValidationException
    and its exact message, while the caller's own 12-digit accountId is not refused with ValidationException."""
    ts = ctx.client("taxsettings")

    # accountId's modeled shape (min/max 12, pattern \d+) is exactly what botocore's
    # own client-side validator enforces, so a client built the ordinary way never
    # transmits "12345" -- it raises ParamValidationError locally, which grades
    # botocore's SDK-side check rather than taxsettings's own rejection. Disable
    # validation so the malformed accountId actually reaches the service.
    unvalidated_ts = ctx.client("taxsettings", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated_ts.get_tax_registration(accountId="12345"))
    assert code == "ValidationException", f"expected ValidationException for a malformed accountId, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'accountId' failed to satisfy constraint: "
        "Member must have length greater than or equal to 12"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    try:
        ts.get_tax_registration(accountId=account_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] != "ValidationException"


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
