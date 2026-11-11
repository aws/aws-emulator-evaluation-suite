"""create-rule-tag-quota-exceeded-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-rule-tag-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating a rule with more than the documented 50-tag-per-rule quota is rejected
    with ServiceQuotaExceededException and no rule is created; exactly 50 tags succeeds."""
    rbin = ctx.client("rbin")

    over_quota_tags = [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(51)]
    marker_description = ctx.unique_name("sim2real-rbin-overquota-")

    error = _error(
        lambda: rbin.create_rule(
            ResourceType="EBS_VOLUME",
            RetentionPeriod={"RetentionPeriodValue": 3, "RetentionPeriodUnit": "DAYS"},
            Tags=over_quota_tags,
            Description=marker_description,
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code!r}"
    assert message == "SERVICE_QUOTA_EXCEEDED", f"expected the exact tag-quota message, got {message!r}"

    matching = [r for r in _list_all(rbin, "EBS_VOLUME") if r.get("Description") == marker_description]
    assert matching == [], "a rule was persisted despite the quota-exceeding create failing"

    # Positive control: exactly the quota (50 tags) is accepted.
    at_quota_tags = [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(50)]
    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 3, "RetentionPeriodUnit": "DAYS"},
        Tags=at_quota_tags,
        Description=ctx.unique_name("sim2real-rbin-atquota-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))
    assert len(rbin.list_tags_for_resource(ResourceArn=_arn_of(rbin, rule_id))["Tags"]) == 50


def _error(fn: Callable[[], Any]) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _list_all(rbin, resource_type: str) -> list[dict]:
    rules: list[dict] = []
    token = None
    while True:
        kwargs = {"ResourceType": resource_type}
        if token:
            kwargs["NextToken"] = token
        resp = rbin.list_rules(**kwargs)
        rules.extend(resp.get("Rules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return rules


def _arn_of(rbin, rule_id: str) -> str:
    return rbin.get_rule(Identifier=rule_id)["RuleArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
