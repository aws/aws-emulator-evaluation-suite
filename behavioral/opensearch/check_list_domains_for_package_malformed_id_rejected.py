"""list-domains-for-package-malformed-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-domains-for-package-malformed-id-rejected"
GROUP = "package"
SERVICES = ["opensearch"]


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success
    raises, because accepting a call AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainsForPackage rejects a PackageID outside its two accepted forms with
    ValidationException and the exact message, while a well-formed id that was never assigned
    to any package succeeds with an empty list rather than erroring."""
    osc = ctx.client("opensearch")

    malformed_id = "bad id!"
    refusal = _error(lambda: osc.list_domains_for_package(PackageID=malformed_id))
    expected_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'packageID' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: "
        f"^([FG][0-9]+)$|^(pkg-[a-f0-9]+)$"
    )
    assert refusal == ("ValidationException", expected_message), (
        f"expected ValidationException with AWS's exact message for a PackageID matching "
        f"neither accepted form, got {refusal!r}"
    )

    # The legal neighbour: a well-formed id (matches the pkg-<hex> form) that was never assigned
    # to a package. ListDomainsForPackage never looks the package up, so it answers with an
    # empty list rather than a not-found error.
    never_assigned_id = "pkg-" + ctx.unique_name("")
    got = osc.list_domains_for_package(PackageID=never_assigned_id)
    assert got["DomainPackageDetailsList"] == [], (
        f"expected no domains for a never-assigned package id, got "
        f"{got['DomainPackageDetailsList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
