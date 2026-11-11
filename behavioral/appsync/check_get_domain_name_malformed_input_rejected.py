"""get-domain-name-malformed-input-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-domain-name-malformed-input-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDomainName does not enforce domainName's pattern or length: a pattern-violating, over-length
    name fails NotFoundException exactly like a well-formed nonexistent domain."""
    # botocore's ParamValidator only enforces `min` length for a string shape (never
    # `max`, never `pattern` -- see botocore.validate.VALIDATED_METADATA_ATTRS), so this
    # value already reaches the wire under default validation. We disable it anyway as a
    # defensive guarantee against a future botocore version tightening that behavior, so
    # this check keeps forcing the malformed value onto the wire to observe the
    # *service's* actual (lack of) validation -- what an emulator must mirror.
    appsync = _client_no_validation(ctx, "appsync")

    # Violates the pattern (a second, non-leading '*' is outside every label's [\w\d-]
    # character class) AND exceeds the documented 253-char maximum length.
    malformed_domain = "*.*." + ("b" * 260) + ".example.com"
    malformed_code, malformed_message = _error(
        lambda: appsync.get_domain_name(domainName=malformed_domain)
    )
    assert malformed_code == "NotFoundException", (
        f"expected NotFoundException (real AWS performs no server-side format/length "
        f"validation for this lookup), got {malformed_code!r}"
    )
    assert malformed_message == "Domain name not found", (
        f"unexpected NotFoundException message {malformed_message!r}"
    )

    wellformed_nonexistent = f"{ctx.unique_name('sim2real-appsync-ctrl').lower()}.example.com"
    control_code, control_message = _error(
        lambda: appsync.get_domain_name(domainName=wellformed_nonexistent)
    )
    assert control_code == "NotFoundException", (
        f"positive control: expected NotFoundException for well-formed nonexistent domain, got {control_code!r}"
    )
    assert control_message == "Domain name not found", (
        f"unexpected NotFoundException message {control_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message).
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected a ClientError (NotFoundException), but the call succeeded and returned {result!r}"
    )


def _client_no_validation(ctx, service):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
