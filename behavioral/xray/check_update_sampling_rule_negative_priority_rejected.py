"""update-sampling-rule-negative-priority-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-sampling-rule-negative-priority-rejected"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSamplingRule with a negative Priority value is rejected rather than silently
    accepted: the stored Priority is left untouched, while a valid Priority update on the
    same rule in the same run still succeeds."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": 500,
            "FixedRate": 0.1,
            "ReservoirSize": 1,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))

    code, message = _error_code(
        lambda: xray.update_sampling_rule(
            SamplingRuleUpdate={"RuleName": rule_name, "Priority": -5}
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = "Invalid update request for sampling rule"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert _current_priority(xray, rule_name) == 500, "rejected update must not have persisted"

    # positive control: a valid priority change on the same rule still succeeds.
    xray.update_sampling_rule(SamplingRuleUpdate={"RuleName": rule_name, "Priority": 501})
    priority_after = _current_priority(xray, rule_name)
    assert priority_after == 501, f"expected positive-control update to persist 501, got {priority_after}"


def _current_priority(xray, rule_name: str) -> int:
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = xray.get_sampling_rules(**kwargs)
        for record in resp["SamplingRuleRecords"]:
            rule = record["SamplingRule"]
            if rule["RuleName"] == rule_name:
                return rule["Priority"]
        token = resp.get("NextToken")
        if not token:
            break
    raise AssertionError(f"sampling rule {rule_name!r} not found")


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
