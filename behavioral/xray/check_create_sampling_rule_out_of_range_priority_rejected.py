"""create-sampling-rule-out-of-range-priority-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-sampling-rule-out-of-range-priority-rejected"
GROUP = "negative-classes"
SERVICES = ["xray"]

EXPECTED_MESSAGE = (
    "1 validation error detected: Value '0' at 'samplingRule.priority' failed to satisfy "
    "constraint: Member must have value greater than or equal to 1"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSamplingRule with Priority 0 (outside 1-9999) fails with ValidationException and the
    exact member-constraint message, no rule is created, and an in-range twin still succeeds."""
    xray = ctx.client("xray")
    lenient = _lenient_client(ctx, "xray")

    bad_name = ctx.unique_name("sim2real-bp-")
    code, message = _error(
        lambda: lenient.create_sampling_rule(SamplingRule=_sampling_rule(bad_name, priority=0))
    )
    assert code == "ValidationException", f"CODE={code} MESSAGE={message!r}"
    assert message == EXPECTED_MESSAGE, f"MESSAGE={message!r}"

    assert bad_name not in _rule_records(xray)

    good_name = ctx.unique_name("sim2real-gp-")
    created = xray.create_sampling_rule(SamplingRule=_sampling_rule(good_name, priority=100))[
        "SamplingRuleRecord"
    ]["SamplingRule"]
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=good_name))
    assert created["Priority"] == 100

    records = _rule_records(xray)
    assert good_name in records, f"positive-control rule {good_name} missing: {sorted(records)!r}"
    assert records[good_name]["Priority"] == 100, records[good_name]


def _rule_records(xray) -> dict:
    records: dict = {}
    token = None
    while True:
        resp = xray.get_sampling_rules(**({"NextToken": token} if token else {}))
        for record in resp["SamplingRuleRecords"]:
            rule = record["SamplingRule"]
            records[rule["RuleName"]] = rule
        token = resp.get("NextToken")
        if not token:
            break
    return records


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


def _lenient_client(ctx, service: str):
    """A client with botocore parameter validation off, so out-of-range values reach the service."""
    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """-> (code, message) of the ClientError `fn` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
