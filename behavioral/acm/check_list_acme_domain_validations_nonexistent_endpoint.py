"""list-acme-domain-validations-nonexistent-endpoint."""
from __future__ import annotations

import time
import uuid
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-acme-domain-validations-nonexistent-endpoint"
GROUP = 'error-semantics'
SERVICES = ['acm']


def _poll_until_active(acm, arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if last["Status"] in ("ACTIVE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"endpoint did not reach a terminal status within {timeout_s}s; last={last!r}")


def _delete_ignoring_not_found(acm, arn):
    try:
        acm.delete_acme_endpoint(AcmeEndpointArn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAcmeDomainValidations scoped to a nonexistent ACME endpoint raises ResourceNotFoundException,
    not an empty page."""
    acm = ctx.client("acm")

    # Positive control: create a real endpoint and list its (empty) domain validations successfully
    # first -- otherwise a target that rejects every ListAcmeDomainValidations call would pass this
    # check for the wrong reason.
    created = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {"AllowedKeyAlgorithms": ["EC_prime256v1"]}},
        Tags=[{"Key": "sim2real-check", "Value": ctx.unique_name("acme-ldv-")}],
    )
    real_arn = created["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(acm, real_arn))

    control = _poll_until_active(acm, real_arn)
    assert control["Status"] == "ACTIVE", f"positive control endpoint did not reach ACTIVE: {control}"

    control_page = acm.list_acme_domain_validations(AcmeEndpointArn=real_arn)
    assert control_page["AcmeDomainValidations"] == [], (
        f"expected the freshly-created endpoint to have no domain validations, "
        f"got {control_page['AcmeDomainValidations']!r}"
    )

    # Derive the bogus ARN by perturbing the real one, not fabricating one from thin air --
    # a fabricated ARN can land outside the probe identity's resource scope and surface
    # AccessDeniedException instead of the not-found semantics under test.
    bogus_arn = real_arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())

    code, message = _error(lambda: acm.list_acme_domain_validations(AcmeEndpointArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent ACME endpoint, got {code!r}"
    )
    expected_message = f"Could not find ACME endpoint {bogus_arn}."
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
