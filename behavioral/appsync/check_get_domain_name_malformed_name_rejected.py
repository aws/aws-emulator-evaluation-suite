"""get-domain-name-malformed-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-domain-name-malformed-name-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDomainName applies no format check: a malformed domain string (no dot, illegal characters)
    fails NotFoundException exactly like a well-formed absent name."""
    appsync = ctx.client("appsync")

    # AppSync's DomainName pattern is ^(\*[\w\d-]*\.)?([\w\d-]+\.)+[\w\d-]+$ -- it requires
    # at least one dot-separated label and forbids underscores/spaces. This string has
    # neither a dot nor a legal character set, so it never matches.
    malformed_domain = "not_a_domain_no_dot"

    code, message = _error(lambda: appsync.get_domain_name(domainName=malformed_domain))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Domain name not found", f"unexpected NotFoundException message {message!r}"

    # Cross-check: CreateDomainName on the SAME malformed string DOES enforce the
    # pattern and is rejected with BadRequestException -- proving the string really is
    # malformed and that Get's NotFoundException above isn't just AWS being lax
    # everywhere, only on the read path.
    create_code, create_message = _error(
        lambda: appsync.create_domain_name(
            domainName=malformed_domain,
            certificateArn=(
                "arn:aws:acm:us-east-1:123456789012:certificate/"
                "00000000-0000-0000-0000-000000000000"
            ),
        )
    )
    assert create_code == "BadRequestException", f"expected BadRequestException, got {create_code}"
    expected_create = (
        f"1 validation error detected: Value '{malformed_domain}' at 'domainName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "^(\\*[\\w\\d-]*\\.)?([\\w\\d-]+\\.)+[\\w\\d-]+$"
    )
    assert create_message == expected_create, (
        f"expected message {expected_create!r}, got {create_message!r}"
    )

    # Positive control: a well-formed domain name that simply doesn't exist takes the
    # SAME error path (NotFoundException) on Get, confirming Get's behavior is identical
    # for malformed-and-absent vs well-formed-and-absent -- it never looks at format.
    well_formed_absent_domain = f"{ctx.unique_name('sim2real-ctrl-')}.example.com".lower()
    control_code, control_message = _error(
        lambda: appsync.get_domain_name(domainName=well_formed_absent_domain)
    )
    assert control_code == "NotFoundException", f"expected NotFoundException, got {control_code}"
    assert control_message == "Domain name not found", (
        f"unexpected NotFoundException message {control_message!r}"
    )

    # Positive control: the domain-name subsystem itself is functional (not blanket-erroring
    # for every call, which would make the NotFoundException above meaningless) -- a plain
    # list call against the same resource family succeeds normally.
    resp = appsync.list_domain_names()
    assert "domainNameConfigs" in resp, f"expected ListDomainNames to succeed, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message).
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
