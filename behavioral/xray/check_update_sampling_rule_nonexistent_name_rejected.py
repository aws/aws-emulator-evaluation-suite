"""update-sampling-rule-nonexistent-name-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-sampling-rule-nonexistent-name-rejected"
GROUP = "error-semantics"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSamplingRule targeting a well-formed rule name that was never created is rejected
    with InvalidRequestException (the rule-must-exist check) rather than implicitly creating it,
    while updating a rule that DOES exist still succeeds (positive control)."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-behav-rule-")
    xray.create_sampling_rule(SamplingRule=_sampling_rule(rule_name, priority=1000))
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))

    # RuleName is at most 32 characters; a longer name fails length validation before the
    # existence check is reached.
    missing_name = ctx.unique_name("sim2real-miss-")
    code, message = _error_code(
        lambda: xray.update_sampling_rule(
            SamplingRuleUpdate={"RuleName": missing_name, "Priority": 500}
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got CODE={code!r}"
    expected_message = "Sampling rule does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no rule was implicitly created under the missing name
    assert _find_rule(xray, missing_name) is None, (
        f"UpdateSamplingRule on nonexistent name {missing_name!r} was rejected with "
        f"{code!r}, but the rule now exists in GetSamplingRules"
    )

    # positive control: updating the rule that DOES exist succeeds, proven by an
    # independent read rather than the mutating call's own response.
    xray.update_sampling_rule(SamplingRuleUpdate={"RuleName": rule_name, "Priority": 500})
    record = _find_rule(xray, rule_name)
    assert record is not None, f"rule {rule_name!r} is missing from GetSamplingRules after update"
    assert record["SamplingRule"]["Priority"] == 500, (
        f"independent read of {rule_name!r} shows Priority="
        f"{record['SamplingRule']['Priority']!r}, expected 500"
    )


def _sampling_rule(name: str, priority: int) -> dict:
    return {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": priority,
        "FixedRate": 0.05,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    }


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _find_rule(xray, rule_name: str) -> dict | None:
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = xray.get_sampling_rules(**kwargs)
        for record in resp.get("SamplingRuleRecords", []):
            if record["SamplingRule"]["RuleName"] == rule_name:
                return record
        next_token = resp.get("NextToken")
        if not next_token:
            return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
