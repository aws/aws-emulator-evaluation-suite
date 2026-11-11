"""op-contract-get-managed-certificate-details."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-managed-certificate-details"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetManagedCertificateDetails 404s (EntityNotFound) for an unknown identifier."""
    cf = ctx.client("cloudfront")

    err, message = _error(lambda: cf.get_managed_certificate_details(Identifier="dt_sim2real0000000000"))
    assert err == "EntityNotFound", f"expected EntityNotFound for an unknown identifier, got {err}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
