"""describe-ssl-policies-malformed-name-format-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-ssl-policies-malformed-name-format-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

# Names has no documented format constraint, but PageSize has a documented 1-400 range, so an
# out-of-range PageSize is this operation's malformed-input case.
_OUT_OF_RANGE_PAGE_SIZE = 100000
_WELL_FORMED_UNKNOWN_NAME = "ELBSecurityPolicy-sim2real-does-not-exist-0000"
_KNOWN_POLICY_NAME = "ELBSecurityPolicy-2016-08"


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSSLPolicies with PageSize outside 1-400 fails with ValidationError, distinct from
    SSLPolicyNotFound for a well-formed unknown name; a real policy lookup still succeeds.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeSSLPolicies.html
    """
    elbv2 = ctx.client("elbv2")
    # Without this, botocore rejects the out-of-range PageSize before any request is sent.
    raw = ctx.client(
        "elbv2",
        config=Config(parameter_validation=False, retries={"max_attempts": 8, "mode": "standard"}),
    )

    code, message = _error(lambda: raw.describe_ssl_policies(PageSize=_OUT_OF_RANGE_PAGE_SIZE))
    assert code == "ValidationError", f"CODE={code!r}"
    assert message == (
        f"1 validation error detected: Value '{_OUT_OF_RANGE_PAGE_SIZE}' at 'pageSize' failed to satisfy "
        "constraint: Member must have value less than or equal to 400"
    ), f"MESSAGE={message!r}"

    not_found_code, not_found_message = _error(
        lambda: elbv2.describe_ssl_policies(Names=[_WELL_FORMED_UNKNOWN_NAME])
    )
    assert not_found_code == "SSLPolicyNotFound", f"CODE={not_found_code!r}"
    assert not_found_message == "One or more SSL policies not found", f"MESSAGE={not_found_message!r}"

    policies = elbv2.describe_ssl_policies(Names=[_KNOWN_POLICY_NAME])["SslPolicies"]
    assert len(policies) == 1, f"expected exactly 1 policy for {_KNOWN_POLICY_NAME!r}, got {policies!r}"
    assert policies[0]["Name"] == _KNOWN_POLICY_NAME, f"NAME={policies[0].get('Name')!r}"
    assert policies[0]["Ciphers"], f"expected a non-empty Ciphers list, got {policies[0].get('Ciphers')!r}"


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
