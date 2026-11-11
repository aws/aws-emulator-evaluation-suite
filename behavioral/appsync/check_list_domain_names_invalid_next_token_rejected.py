"""list-domain-names-invalid-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-domain-names-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDomainNames called with a corrupted (undecodable) nextToken is rejected with
    BadRequestException rather than silently returning an empty/garbage page."""
    appsync = ctx.client("appsync")

    # This satisfies the nextToken shape's own client-side pattern (non-whitespace,
    # 1-65536 chars) but is not a token the service ever issued, so it cannot be decoded.
    corrupted_token = "not-a-real-appsync-pagination-token-0000000000"

    code, message = _error(lambda: appsync.list_domain_names(nextToken=corrupted_token))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid pagination token given.", f"unexpected BadRequestException message {message!r}"

    # Positive control: the same call without a nextToken succeeds normally, proving the
    # rejection above is specific to the corrupted token and not a blanket failure.
    resp = appsync.list_domain_names()
    assert "domainNameConfigs" in resp, f"expected domainNameConfigs in response, got {resp!r}"


def _error(fn) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
