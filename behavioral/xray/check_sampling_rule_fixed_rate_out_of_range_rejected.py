"""sampling-rule-fixed-rate-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sampling-rule-fixed-rate-out-of-range-rejected"
GROUP = "representation"
SERVICES = ["xray"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_rule_if_present(xray, name: str) -> None:
    """Teardown for a rule that exists only on a target that wrongly accepted it."""
    if name in _rule_names(xray):
        xray.delete_sampling_rule(RuleName=name)


def _base_rule(name: str, fixed_rate: float) -> dict:
    return {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": 9000,
        "FixedRate": fixed_rate,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    }


def _rule_names(xray) -> set:
    names: set = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = xray.get_sampling_rules(**kwargs)
        names.update(r["SamplingRule"]["RuleName"] for r in resp["SamplingRuleRecords"])
        token = resp.get("NextToken")
        if not token:
            break
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSamplingRule refuses FixedRate 1.5 with ValidationException naming the fixedRate
    range and creates no rule, while FixedRate 0.5 is created and listed."""
    xray = ctx.client("xray")

    # RuleName has a 32-char max, so keep the prefix short (unique_name appends 12 hex chars).
    bad_name = ctx.unique_name("sim2real-xr-bad-")
    # Registered before the call: if an over-permissive target actually creates this rule
    # instead of rejecting it, the resource must not leak untracked.
    ctx.on_cleanup(lambda: _delete_rule_if_present(xray, bad_name))
    code, message = _error_code(
        lambda: xray.create_sampling_rule(
            SamplingRule=_base_rule(bad_name, 1.5), Tags=[{"Key": "sim2real", "Value": CHECK}]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '1.5' at 'samplingRule.fixedRate' failed to satisfy "
        "constraint: Member must have value less than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    assert bad_name not in _rule_names(xray), "rule with out-of-range FixedRate should not have been created"

    good_name = ctx.unique_name("sim2real-xr-good-")
    created = xray.create_sampling_rule(
        SamplingRule=_base_rule(good_name, 0.5), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["SamplingRuleRecord"]["SamplingRule"]
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=good_name))
    assert created["FixedRate"] == 0.5, f"expected FixedRate 0.5, got {created['FixedRate']!r}"
    assert good_name in _rule_names(xray), f"positive-control rule {good_name!r} not visible via get_sampling_rules"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
