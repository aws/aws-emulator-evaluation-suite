"""get-email-address-insights-malformed-address-low-syntax-verdict."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-email-address-insights-malformed-address-low-syntax-verdict"
GROUP = "overly-permissive"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEmailAddressInsights gives a LOW HasValidSyntax verdict for a string with no '@' and a
    HIGH one for a well-formed address, rather than a fixed verdict that ignores the input."""
    ses = ctx.client("sesv2")

    # A malformed address is not an error: the call returns 200 with the verdict in the body.
    malformed = ses.get_email_address_insights(EmailAddress="this is not an email at all")
    malformed_syntax_verdict = (
        malformed.get("MailboxValidation", {})
        .get("Evaluations", {})
        .get("HasValidSyntax", {})
        .get("ConfidenceVerdict")
    )
    assert malformed_syntax_verdict == "LOW", malformed_syntax_verdict

    # Positive control: proves the LOW verdict above is discrimination, not a blanket LOW.
    wellformed = ses.get_email_address_insights(EmailAddress="sim2real-insights-probe@example.com")
    wellformed_syntax_verdict = (
        wellformed.get("MailboxValidation", {})
        .get("Evaluations", {})
        .get("HasValidSyntax", {})
        .get("ConfidenceVerdict")
    )
    assert wellformed_syntax_verdict == "HIGH", wellformed_syntax_verdict


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
