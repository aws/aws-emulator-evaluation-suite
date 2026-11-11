"""describe-ssl-policies-unknown-name-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-ssl-policies-unknown-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSSLPolicies for a nonexistent policy name fails with SSLPolicyNotFound, while a known managed policy still resolves."""

    elb = ctx.client("elbv2")

    def _error(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        for attempt in range(attempts):
            try:
                result = fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    return code, exc.response.get("Error", {}).get("Message")
                time.sleep(delays[min(attempt, len(delays) - 1)])
                continue
            raise AssertionError(
                f"expected DescribeSSLPolicies to raise for an unknown name, "
                f"but it SUCCEEDED and returned {result!r}"
            )
        raise AssertionError(f"still throttled after {attempts} attempts")

    code, message = _error(
        lambda: elb.describe_ssl_policies(Names=["sim2real-behav-no-such-policy"])
    )
    assert code == "SSLPolicyNotFound", (
        f"expected SSLPolicyNotFound for an unknown policy name, got {code!r}"
    )
    assert message == "One or more SSL policies not found", f"MESSAGE={message!r}"

    real = elb.describe_ssl_policies(Names=["ELBSecurityPolicy-2016-08"])["SslPolicies"]
    assert real and real[0]["Name"] == "ELBSecurityPolicy-2016-08", (
        f"expected the known managed policy ELBSecurityPolicy-2016-08 to resolve, got {real!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
