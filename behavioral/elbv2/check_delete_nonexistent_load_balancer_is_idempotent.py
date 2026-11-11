"""delete-nonexistent-load-balancer-is-idempotent."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-load-balancer-is-idempotent"
GROUP = 'load-balancer-lifecycle'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLoadBalancer on a never-existing ARN succeeds (unlike DescribeLoadBalancers, which raises
    LoadBalancerNotFound), and the ARN stays absent before and after the delete."""

    _acct_cache = {}
    elb = ctx.client("elbv2")

    def _error_code(fn):
        delays = [3, 6, 12, 24, 30]
        code = message = None
        for attempt in range(5):
            try:
                fn()
                code = message = None
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                message = exc.response.get("Error", {}).get("Message")
            if code not in _THROTTLE_CODES:
                return code, message
            time.sleep(delays[attempt])
        return code, message

    def _account_id():
        if "id" not in _acct_cache:
            _acct_cache["id"] = ctx.client("sts").get_caller_identity()["Account"]
        return _acct_cache["id"]

    def _fake_lb_arn(name="ghost-lb"):
        return f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:loadbalancer/app/{name}/0123456789abcdef"

    arn = _fake_lb_arn()

    def _describe_code():
        return _error_code(lambda: elb.describe_load_balancers(LoadBalancerArns=[arn]))

    pre_code, pre_message = _describe_code()
    assert pre_code == "LoadBalancerNotFound", f"expected the fake ARN to be genuinely absent before delete, got {pre_code}"
    assert pre_message == "One or more load balancers not found", pre_message

    code, _ = _error_code(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
    assert code is None, f"expected idempotent success, got error {code}"

    post_code, post_message = _describe_code()
    assert post_code == "LoadBalancerNotFound", (
        f"delete on a never-existing ARN must not fabricate a resolvable entry, got {post_code}"
    )
    assert post_message == "One or more load balancers not found", post_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
