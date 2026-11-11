"""get-tax-registration-document-invalid-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-tax-registration-document-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTaxRegistrationDocument with a fabricated access token is refused with ValidationException, its exact
    message, errorCode MalformedToken and a fieldList naming TAX_DOC_ACCESS_TOKEN; ListTaxRegistrations answers
    as the control."""
    ts = ctx.client("taxsettings")

    list_resp = ts.list_tax_registrations()
    assert "accountDetails" in list_resp, f"ListTaxRegistrations returned no accountDetails: {list_resp!r}"

    try:
        ts.get_tax_registration_document(
            taxDocumentMetadata={
                "taxDocumentAccessToken": "sim2real-not-a-real-token",
                "taxDocumentName": "sim2real-doc.pdf",
            }
        )
        raise AssertionError("expected ValidationException for a fabricated access token, got a successful response")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", f"expected ValidationException, got {code!r}"
        expected = (
            "The specified token in the request is either malformed or incorrect. "
            "Check your request and try again."
        )
        message = exc.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"
        # botocore surfaces this operation's modeled ValidationException members
        # (errorCode, fieldList) at the top level of exc.response, alongside --
        # not nested under -- the generic Error.Code/Message pair.
        assert exc.response.get("errorCode") == "MalformedToken", (
            f"expected the modeled errorCode MalformedToken, got {exc.response.get('errorCode')!r}"
        )
        field_names = {f.get("name") for f in (exc.response.get("fieldList") or [])}
        assert "TAX_DOC_ACCESS_TOKEN" in field_names, (
            f"expected fieldList to name TAX_DOC_ACCESS_TOKEN, got {field_names!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
