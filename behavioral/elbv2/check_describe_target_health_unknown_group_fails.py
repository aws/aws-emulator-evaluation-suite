"""describe-target-health-unknown-group-fails."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-target-health-unknown-group-fails"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTargetHealth on a nonexistent target group ARN fails with TargetGroupNotFound and the exact message,
    while a real, empty target group returns no TargetHealthDescriptions."""

    _acct_cache = {}
    elb = ctx.client("elbv2")

    def _error(fn):
        """Return the AWS error (code, message), or raise if the call unexpectedly SUCCEEDED.

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
                    return code, exc.response.get("Error", {}).get("Message")
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

    def _fake_target_group_arn(name="ghost-tg"):
        return f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:targetgroup/{name}/0123456789abcdef"

    tg_name = ctx.unique_name("sim2real-tgh-")[:32].rstrip("-")
    tg_arn = elb.create_target_group(
        Name=tg_name, TargetType="lambda",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=tg_arn))

    positive = elb.describe_target_health(TargetGroupArn=tg_arn)
    assert positive["TargetHealthDescriptions"] == [], (
        f"positive control failed: expected no registered targets, got "
        f"{positive['TargetHealthDescriptions']!r}"
    )

    fake_arn = _fake_target_group_arn()
    code, message = _error(
        lambda: elb.describe_target_health(
            TargetGroupArn=fake_arn,
            Targets=[{"Id": "10.0.9.99", "Port": 80}],
        )
    )
    assert code == "TargetGroupNotFound", f"expected not-found error, got {code}"
    assert message == f"Target groups '{fake_arn}' not found", f"MESSAGE={message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
