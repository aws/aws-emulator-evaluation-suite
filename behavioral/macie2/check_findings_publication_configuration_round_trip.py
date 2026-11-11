"""findings-publication-configuration-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "findings-publication-configuration-round-trip"
GROUP = "data-plane"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """PutFindingsPublicationConfiguration persists the Security Hub publication flags exactly as written."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")

    original = macie.get_findings_publication_configuration().get("securityHubConfiguration")
    ctx.on_cleanup(lambda: _restore(macie, original))

    macie.put_findings_publication_configuration(
        securityHubConfiguration={"publishClassificationFindings": True, "publishPolicyFindings": False}
    )
    updated = macie.get_findings_publication_configuration()["securityHubConfiguration"]
    assert updated["publishClassificationFindings"] is True, (
        f"expected publishClassificationFindings=True after put, got {updated['publishClassificationFindings']!r}"
    )
    assert updated["publishPolicyFindings"] is False, (
        f"expected publishPolicyFindings=False after put, got {updated['publishPolicyFindings']!r}"
    )

    macie.put_findings_publication_configuration(
        securityHubConfiguration={"publishClassificationFindings": False, "publishPolicyFindings": True}
    )
    flipped = macie.get_findings_publication_configuration()["securityHubConfiguration"]
    assert flipped["publishClassificationFindings"] is False, (
        f"expected publishClassificationFindings=False after flip, got {flipped['publishClassificationFindings']!r}"
    )
    assert flipped["publishPolicyFindings"] is True, (
        f"expected publishPolicyFindings=True after flip, got {flipped['publishPolicyFindings']!r}"
    )


def _restore(macie, original) -> None:
    from botocore.exceptions import ClientError

    if original is None:
        return
    try:
        macie.put_findings_publication_configuration(securityHubConfiguration=original)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
