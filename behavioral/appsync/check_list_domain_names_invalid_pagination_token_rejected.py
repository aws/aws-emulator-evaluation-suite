"""list-domain-names-invalid-pagination-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-domain-names-invalid-pagination-token-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainNames called with a corrupted/foreign nextToken is rejected with
    BadRequestException instead of returning an arbitrary page, while the same call
    with no token (the positive control) succeeds normally."""
    appsync = ctx.client("appsync")

    # Satisfies the PaginationToken wire pattern (^[\S]+$, no whitespace) so it is not
    # rejected by client-side pattern validation -- it is simply not a real, previously
    # issued continuation token, which the service must detect server-side.
    foreign_token = "sim2real-foreign-continuation-token-0123456789abcdef"
    code, message = _error(lambda: appsync.list_domain_names(nextToken=foreign_token))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid pagination token given.", f"unexpected BadRequestException message {message!r}"

    # Positive control: the same operation, same credentials, no token -> must succeed.
    resp = appsync.list_domain_names()
    assert "domainNameConfigs" in resp, f"expected domainNameConfigs in response, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a foreign token real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
