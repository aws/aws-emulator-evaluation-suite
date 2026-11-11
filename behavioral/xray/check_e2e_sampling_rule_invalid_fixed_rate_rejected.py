"""e2e-sampling-rule-invalid-fixed-rate-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-sampling-rule-invalid-fixed-rate-rejected"
GROUP = "e2e"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSamplingRule rejects a FixedRate outside the documented [0,1] range with
    ValidationException, leaves no such rule behind, while a rule with a valid FixedRate
    in the same call shape still succeeds."""
    xray = ctx.client("xray")
    bad_rule_name = ctx.unique_name("sim2real-badrate-")[:32]
    good_rule_name = ctx.unique_name("sim2real-goodrate-")[:32]

    def _bad_call():
        return xray.create_sampling_rule(
            SamplingRule={
                "RuleName": bad_rule_name,
                "ResourceARN": "*",
                "Priority": 9600,
                "FixedRate": 2.5,  # out of the documented Minimum 0 / Maximum 1 range
                "ReservoirSize": 1,
                "ServiceName": "*",
                "ServiceType": "*",
                "Host": "*",
                "HTTPMethod": "*",
                "URLPath": "*",
                "Version": 1,
            }
        )

    code, message = _error(_bad_call)
    assert code == "ValidationException", f"expected ValidationException, got code={code!r}"
    assert message == (
        "1 validation error detected: Value '2.5' at 'samplingRule.fixedRate' failed to satisfy "
        "constraint: Member must have value less than or equal to 1"
    ), f"unexpected message: {message!r}"

    names_after_failure = _rule_names(xray)
    assert bad_rule_name not in names_after_failure, (
        f"rejected rule {bad_rule_name!r} leaked into GetSamplingRules: {sorted(names_after_failure)!r}"
    )

    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": good_rule_name,
            "ResourceARN": "*",
            "Priority": 9600,
            "FixedRate": 0.1,
            "ReservoirSize": 1,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }
    )
    ctx.on_cleanup(lambda: _delete_rule_if_present(xray, good_rule_name))

    records = _rule_records(xray)
    matches = [r for r in records if r["SamplingRule"]["RuleName"] == good_rule_name]
    assert matches, f"good rule {good_rule_name!r} missing from GetSamplingRules: {sorted(r['SamplingRule']['RuleName'] for r in records)!r}"
    good = matches[0]
    assert good["SamplingRule"]["FixedRate"] == 0.1, f"expected FixedRate=0.1, got {good['SamplingRule']['FixedRate']!r}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    ACCEPTING input real AWS refuses is the strongest signal available and must not be reduced
    to an error-code mismatch. A ParamValidationError is deliberately left to
    propagate uncaught: it means the request never left the SDK, which is a different failure
    than a server-side rejection and must not be counted as one."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _rule_records(xray) -> list:
    pages = xray.get_paginator("get_sampling_rules").paginate()
    return [r for page in pages for r in page["SamplingRuleRecords"]]


def _rule_names(xray) -> set:
    return {r["SamplingRule"]["RuleName"] for r in _rule_records(xray)}


def _delete_rule_if_present(xray, rule_name: str) -> None:
    """Teardown: "Sampling rule does not exist" is clean; any other refusal is a failure."""
    from botocore.exceptions import ClientError

    try:
        xray.delete_sampling_rule(RuleName=rule_name)
    except ClientError as e:
        if e.response.get("Error", {}).get("Message") != "Sampling rule does not exist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
