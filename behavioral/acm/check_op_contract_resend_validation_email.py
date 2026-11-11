"""op-contract-resend-validation-email."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-resend-validation-email"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResendValidationEmail right after an EMAIL-validated RequestCertificate is refused with the
    in-progress InvalidStateException, then succeeds once the initial email is dispatched; on a
    DNS-validated certificate the settled refusal says it is not using EMAIL validation."""
    acm = ctx.client("acm")
    domain = _domain(ctx)
    other_domain = _domain(ctx)

    arn = acm.request_certificate(DomainName=domain, ValidationMethod="EMAIL")["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))

    # Called at once after RequestCertificate, before the initial validation email is
    # dispatched, so the refusal is the in-progress one.
    code, message = _client_error(
        lambda: acm.resend_validation_email(
            CertificateArn=arn, Domain=domain, ValidationDomain=domain
        )
    )
    assert code == "InvalidStateException", f"expected InvalidStateException, got {code}"
    assert message == _IN_PROGRESS, f"expected {_IN_PROGRESS!r}, got {message!r}"

    # DomainValidationOptions is populated asynchronously and can be absent from the
    # first describe, so it is polled for.
    detail = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"],
        lambda d: bool(d.get("DomainValidationOptions")),
    )
    assert detail["Status"] == "PENDING_VALIDATION"
    validation_domains = {o["DomainName"] for o in detail["DomainValidationOptions"]}
    assert domain in validation_domains

    # the rejected resend attempt didn't affect the certificate's validation
    # state or domain list
    still = acm.describe_certificate(CertificateArn=arn)["Certificate"]
    assert still["Status"] == "PENDING_VALIDATION"
    assert {o["DomainName"] for o in still["DomainValidationOptions"]} == validation_domains

    # Positive control: once the initial-dispatch gate clears, the identical call succeeds,
    # so a target that refuses every resend cannot pass.
    resp = _retry_while_gated(
        lambda: acm.resend_validation_email(CertificateArn=arn, Domain=domain, ValidationDomain=domain)
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    # a DNS-validated certificate on a different domain, used to exercise the
    # same still-PENDING_VALIDATION gate independently of the EMAIL
    # certificate's initial-dispatch timing.
    dns_arn = acm.request_certificate(DomainName=other_domain, ValidationMethod="DNS")[
        "CertificateArn"
    ]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=dns_arn))
    dns_detail = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=dns_arn)["Certificate"],
        lambda d: bool(d.get("DomainValidationOptions")),
    )
    assert dns_detail["Status"] == "PENDING_VALIDATION"

    # error boundary 2: ResendValidationEmail on a DNS-validated certificate's own
    # domain rejects with InvalidStateException. While the request is still settling
    # the message is the in-progress one; the bounded wait grades the settled refusal,
    # whose message names the certificate and domain.
    code, message = _settled_refusal(
        lambda: acm.resend_validation_email(
            CertificateArn=dns_arn, Domain=other_domain, ValidationDomain=other_domain
        )
    )
    expected = f"Certificate {dns_arn} is not using EMAIL validation for domain {other_domain}"
    assert code == "InvalidStateException", f"expected InvalidStateException, got {code}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    dns_still = acm.describe_certificate(CertificateArn=dns_arn)["Certificate"]
    assert dns_still["Status"] == "PENDING_VALIDATION"


def _poll_until(fetch, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = fetch()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = fetch()
    return result


_IN_PROGRESS = "The certificate request is still in progress. Try again later"


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


def _settled_refusal(fn, attempts: int = 15, delay_s: float = 4.0):
    """(code, message) of fn's refusal once it is no longer the in-progress one;
    raises if it stays in progress for the whole bound."""
    for _ in range(attempts):
        code, message = _client_error(fn)
        if message != _IN_PROGRESS:
            return code, message
        time.sleep(delay_s)
    raise AssertionError(f"the refusal stayed {_IN_PROGRESS!r} for {attempts * delay_s:.0f}s")


def _retry_while_gated(fn, attempts: int = 15, delay_s: float = 6.0):
    """Bounded retry for a resend call that reports InvalidStateException ("still
    in progress") while the initial-dispatch gate is up. Returns the response on
    success; any other error, or a gate that never clears, raises."""
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message")
            if code != "InvalidStateException" or message != _IN_PROGRESS:
                raise AssertionError(f"expected the gate to clear, got {code}: {message!r}")
            time.sleep(delay_s)
    raise AssertionError(
        f"initial-dispatch gate did not clear within {attempts * delay_s:.0f}s"
    )


def _domain(ctx) -> str:
    # Not an RFC 2606 reserved domain: ACM drives those to a terminal state that refuses
    # every resend, so the EMAIL positive control would never clear.
    return f"{ctx.unique_name('sim2real-acm-')}.com".lower()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

