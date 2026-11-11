"""test-custom-data-identifier-match-count-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "test-custom-data-identifier-match-count-roundtrip"
GROUP = "data-plane"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:macie")
def run(ctx) -> None:
    """TestCustomDataIdentifier evaluates the regex against sampleText and returns the exact match
    count -- and, when keywords/ignoreWords are given, a count that reflects Macie's proximity and
    exclusion rules rather than a plain regex-only match count."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    regex = r"\d{3}-\d{2}-\d{4}"

    # "backup" (offset 27) sits between the two matches (offsets 14-25 and 38-49), so it can only
    # ever precede the second one -- a keyword requirement is not satisfiable for the first match.
    sample_text = "Contacts: SSN 123-45-6789, backup SSN 987-65-4321, and a phone 555-1212."

    result = macie.test_custom_data_identifier(regex=regex, sampleText=sample_text)
    assert result["matchCount"] == 2, f"plain regex match: expected matchCount=2, got {result['matchCount']!r}"

    no_match = macie.test_custom_data_identifier(
        regex=regex,
        sampleText="No sensitive numbers of that shape here at all.",
    )
    assert no_match["matchCount"] == 0, f"no-match text: expected matchCount=0, got {no_match['matchCount']!r}"

    # keywords gate: a required keyword must precede AND be within maximumMatchDistance of a match.
    # "backup" never appears before the first SSN, so only the second SSN can qualify -- a stub that
    # ignores keywords and just counts regex matches would return 2 here, not 1.
    keyword_gated = macie.test_custom_data_identifier(
        regex=regex,
        sampleText=sample_text,
        keywords=["backup"],
        maximumMatchDistance=300,
    )
    assert keyword_gated["matchCount"] == 1, (
        f"keyword-gated match: expected matchCount=1 (only the SSN preceded by 'backup'), "
        f"got {keyword_gated['matchCount']!r}"
    )

    # ignoreWords: a match whose matched text contains a listed ignore word is excluded outright.
    # A stub that just counts regex matches would return 2 here too, not 1.
    ignored = macie.test_custom_data_identifier(
        regex=regex,
        sampleText=sample_text,
        ignoreWords=["987-65-4321"],
    )
    assert ignored["matchCount"] == 1, (
        f"ignore-word match: expected matchCount=1 (the ignored SSN excluded), got {ignored['matchCount']!r}"
    )


def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
