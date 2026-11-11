"""search-certificates-invalid-filter-rejected."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-certificates-invalid-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SearchCertificates rejects a FilterStatement that sets more than one member of the
    CertificateFilterStatement union (And + Or simultaneously) with ValidationException,
    while a single well-formed member succeeds."""
    acm = ctx.client("acm")
    account = _account_id(ctx)
    fake_cert_arn = f"arn:aws:acm:{ctx.region}:{account}:certificate/{uuid.uuid4()}"

    # Positive control: exactly one union member (Filter) set -> succeeds (0 or more results).
    ok = acm.search_certificates(
        FilterStatement={"Filter": {"CertificateArn": fake_cert_arn}}
    )
    assert "Results" in ok, f"expected a Results collection for a single-member filter, got {sorted(ok.keys())!r}"

    # Negative: CertificateFilterStatement is a tagged union - only one of And/Or/Not/Filter
    # may be specified. Setting both And and Or is invalid. botocore's own parameter validator
    # enforces "exactly one member of a tagged union" and raises a local ParamValidationError
    # before any request is sent, which would mean the TARGET never sees the malformed input --
    # an emulator that happily accepts a multi-member union and returns results would still be
    # graded green. Disable client-side parameter validation so the bad request actually goes on
    # the wire and it is the service's own rejection that gets asserted.
    unvalidated_acm = ctx.client("acm", config=Config(parameter_validation=False))
    bad_statement = {
        "And": [{"Filter": {"CertificateArn": fake_cert_arn}}],
        "Or": [{"Filter": {"CertificateArn": fake_cert_arn}}],
    }
    code, message = _client_error(
        lambda: unvalidated_acm.search_certificates(FilterStatement=bad_statement)
    )
    assert code == "ValidationException", (
        f"expected a server-side ValidationException for a multi-member filter union, got {code!r}"
    )
    expected = (
        "Each CertificateFilterStatement must contain exactly one member. "
        "A CertificateFilterStatement in your request contains the members [And, Or]."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
