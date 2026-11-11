"""create-agreement-request-invalid-intent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-agreement-request-invalid-intent-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-agreement"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAgreementRequest with an intent outside NEW/AMEND/REPLACE is refused with
    ValidationException "Provided intent is invalid.", while a valid intent with an inactive proposal
    gets the proposal's own ValidationException message.
    """
    # marketplace-agreement is served only from us-east-1, so every target is addressed there.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")
    requested_terms = [{"id": ctx.unique_name("sim2real-term-")}]

    bad_code = _error_code(
        lambda: mpa.create_agreement_request(
            intent="SUPERSEDE_EVERYTHING",
            requestedTerms=requested_terms,
        )
    )
    want_bad = ("ValidationException", "Provided intent is invalid.")
    assert bad_code == want_bad, f"expected {want_bad!r}, got {bad_code!r}"

    # Positive control: the same shape of call with a *valid* intent enum value clears the
    # enum check; the fabricated proposal identifier is well-formed but doesn't reference a
    # real, active proposal, so real AWS answers with a *different* ValidationException reason
    # ("Provided agreement proposal is inactive") rather than the intent-enum rejection --
    # proving the bad case above really is about the intent enum, not a blanket failure.
    control_code = _error_code(
        lambda: mpa.create_agreement_request(
            intent="NEW",
            requestedTerms=requested_terms,
            agreementProposalIdentifier="ap-sim2realnonexistentproposal",
        )
    )
    want_control = ("ValidationException", "Provided agreement proposal is inactive.")
    assert control_code == want_control, f"expected {want_control!r}, got {control_code!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
