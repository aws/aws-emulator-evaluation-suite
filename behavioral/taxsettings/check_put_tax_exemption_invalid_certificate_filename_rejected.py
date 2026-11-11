"""put-tax-exemption-invalid-certificate-filename-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-tax-exemption-invalid-certificate-filename-rejected"
GROUP = "error-semantics"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTaxExemption with a .txt exemption certificate documentName is refused with ValidationException and the
    exact message naming exemptionCertificate.documentName."""
    ts = ctx.client("taxsettings")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    error = _error(
        lambda: ts.put_tax_exemption(
            accountIds=[account_id],
            authority={"country": "US"},
            exemptionType="StateSalesTaxExemption",
            exemptionCertificate={
                "documentName": "sim2real-cert.txt",
                "documentFile": b"sim2real-dummy-bytes",
            },
        )
    )
    code, message = error
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    expected = (
        "1 validation error detected: Value at 'exemptionCertificate.documentName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "([A-Za-z0-9_.-]+)\\.([pP][dD][fF]|[jJ][pP][gG]|[pP][nN][gG])"
    )
    assert message == expected, (
        f"expected the rejection to name exemptionCertificate.documentName with the exact "
        f"message {expected!r}, got: {message!r}"
    )


def _error(fn):
    """The rejected call's (code, message); an unexpected success raises, so an emulator that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"expected PutTaxExemption to reject a .txt certificate, but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
