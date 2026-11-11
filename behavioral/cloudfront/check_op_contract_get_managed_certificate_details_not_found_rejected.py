"""op-contract-get-managed-certificate-details-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-managed-certificate-details-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetManagedCertificateDetails answers an Identifier that names no distribution tenant with EntityNotFound and
    the exact message "The specified distribution tenant doesn't exist."."""
    cf = ctx.client("cloudfront")
    code, message = _error(
        lambda: cf.get_managed_certificate_details(Identifier="dt-sim2real-bogus-cert-0000000000")
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting a lookup AWS refuses
    is a finding in itself, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this lookup with EntityNotFound, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
