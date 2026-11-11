"""describe-ssl-policies-malformed-name-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-ssl-policies-malformed-name-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["elbv2"]

# Policy names are short, fixed, hyphenated tokens (e.g. "ELBSecurityPolicy-2016-08"); a
# 300-character string blows past any real policy name's length and is a deterministic,
# unambiguous "malformed" filter value that doesn't rely on special characters that could
# trip up transport-layer parsing.
_MALFORMED_NAME = "x" * 300
_VALID_NAME = "ELBSecurityPolicy-2016-08"
_NOT_FOUND_MESSAGE = "One or more SSL policies not found"


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSSLPolicies with a malformed Names entry fails with SSLPolicyNotFound and the exact message, alone
    or mixed with a real policy name, while the real policy name alone returns that one policy."""
    elbv2 = ctx.client("elbv2")

    code, message = _error(lambda: elbv2.describe_ssl_policies(Names=[_MALFORMED_NAME]))
    assert code == "SSLPolicyNotFound", f"expected SSLPolicyNotFound, got {code!r}"
    assert message == _NOT_FOUND_MESSAGE, f"MESSAGE={message!r}"

    # a malformed entry poisons the whole request -- no partial list comes back even though
    # one of the two names is a real, valid predefined policy
    mixed_code, mixed_message = _error(
        lambda: elbv2.describe_ssl_policies(Names=[_VALID_NAME, _MALFORMED_NAME])
    )
    assert mixed_code == "SSLPolicyNotFound", f"expected SSLPolicyNotFound, got {mixed_code!r}"
    assert mixed_message == _NOT_FOUND_MESSAGE, f"MESSAGE={mixed_message!r}"

    # positive control: the valid name alone succeeds and returns exactly that policy
    resp = elbv2.describe_ssl_policies(Names=[_VALID_NAME])
    assert len(resp["SslPolicies"]) == 1, resp
    assert resp["SslPolicies"][0]["Name"] == _VALID_NAME, resp


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

