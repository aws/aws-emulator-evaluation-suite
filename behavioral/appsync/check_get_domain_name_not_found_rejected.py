"""get-domain-name-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-domain-name-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDomainName for a domain name that was never registered returns NotFoundException."""
    appsync = ctx.client("appsync")

    # Syntactically-valid domain name (matches AppSync's DomainName pattern) that was
    # never created via CreateDomainName.
    fake_domain = f"{ctx.unique_name('sim2real-nodomain-')}.example.com".lower()

    code, message = _error(lambda: appsync.get_domain_name(domainName=fake_domain))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Domain name not found", f"unexpected NotFoundException message {message!r}"

    # Positive control: the domain-name subsystem itself is functional (not blanket-erroring) --
    # a plain list call against the same resource family succeeds normally.
    resp = appsync.list_domain_names()
    assert "domainNameConfigs" in resp, f"expected domainNameConfigs in response, got {resp!r}"


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
