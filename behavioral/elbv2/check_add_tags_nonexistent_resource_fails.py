"""add-tags-nonexistent-resource-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-tags-nonexistent-resource-fails"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTags on a nonexistent load balancer ARN fails with LoadBalancerNotFound and the exact message, while
    AddTags on a real target group applies a tag that DescribeTags reads back."""

    _acct_cache = {}
    elb = ctx.client("elbv2")

    def _error_code(fn):
        """Return the AWS (code, message), or raise if the call unexpectedly SUCCEEDED.

        Returning a falsy sentinel on success would turn the strongest possible signal — the
        service accepting input real AWS rejects — into a code mismatch that reads like a
        naming difference.
        """
        delays = [3, 6, 12, 24, 30]
        for attempt in range(5):
            try:
                result = fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    return code, exc.response["Error"].get("Message")
                time.sleep(delays[attempt])
                continue
            raise AssertionError(
                f"call was expected to be rejected but SUCCEEDED, returning {result!r}"
            )
        raise AssertionError("exhausted retries waiting out throttling")

    def _account_id():
        if "id" not in _acct_cache:
            _acct_cache["id"] = ctx.client("sts").get_caller_identity()["Account"]
        return _acct_cache["id"]

    def _fake_lb_arn(name="ghost-lb"):
        return f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:loadbalancer/app/{name}/0123456789abcdef"

    tg_name = ctx.unique_name("sim2real-addtags-")[:32].rstrip("-")
    tg_arn = elb.create_target_group(
        Name=tg_name, TargetType="lambda",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=tg_arn))

    elb.add_tags(ResourceArns=[tg_arn], Tags=[{"Key": "env", "Value": "test"}])
    described = elb.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in described}
    assert tag_map.get("env") == "test", f"positive control failed: expected env=test, got {tag_map!r}"

    fake_lb_arn = _fake_lb_arn()
    code, message = _error_code(
        lambda: elb.add_tags(
            ResourceArns=[fake_lb_arn], Tags=[{"Key": "env", "Value": "test"}]
        )
    )
    assert code == "LoadBalancerNotFound", f"expected not-found error, got {code}"
    expected_message = "One or more load balancers not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
