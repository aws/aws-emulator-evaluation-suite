"""create-sampling-rule-attributes-exceed-max-rejected."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-sampling-rule-attributes-exceed-max-rejected"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _default_sampling_rule(name, **overrides):
    rule = {
        "RuleName": name,
        "ResourceARN": "*",
        "Priority": random.randint(1, 9999),
        "FixedRate": 0.05,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    }
    rule.update(overrides)
    return rule


def _poll_until(probe, predicate, timeout_s=60, interval_s=2, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _sampling_rule_records(xr, max_pages=25):
    out = {}
    token = None
    for _ in range(max_pages):
        page = xr.get_sampling_rules(**({"NextToken": token} if token else {}))
        for record in page.get("SamplingRuleRecords", []):
            name = (record.get("SamplingRule") or {}).get("RuleName")
            if name:
                out[name] = record
        token = page.get("NextToken")
        if not token:
            break
    return out


def _delete_rule_and_confirm(xr, rule_name, timeout_s=60):
    xr.delete_sampling_rule(RuleName=rule_name)
    _poll_until(
        lambda: _sampling_rule_records(xr),
        lambda records: rule_name not in records,
        timeout_s=timeout_s,
        interval_s=2,
        description=f"sampling rule {rule_name} absent from GetSamplingRules after delete",
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSamplingRule refuses 6 Attributes (modelled max 5) server-side with
    ValidationException naming the length constraint and creates no rule; a 5-attribute rule
    round-trips unchanged."""
    xr = ctx.client("xray")

    # Valid setup: the maximum permitted number of attributes.
    at_max = {f"probe_key_{i}": f"probe_value_{i}" for i in range(5)}
    good = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"), Attributes=at_max)
    good_name = good["RuleName"]
    created = xr.create_sampling_rule(SamplingRule=good)["SamplingRuleRecord"]
    ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, good_name))
    assert created["SamplingRule"]["Attributes"] == at_max, (
        f"exactly 5 attributes is legal and must round-trip, got {created!r}"
    )

    # Break exactly one thing: one attribute over the modelled maximum.
    over_max = dict(at_max, probe_key_5="probe_value_5")
    assert len(over_max) == 6, f"test setup must exceed the modelled max of 5 by exactly 1, got {len(over_max)}"
    bad = _default_sampling_rule(ctx.unique_name("sim2real-behav-r-"), Attributes=over_max)
    bad_name = bad["RuleName"]
    try:
        accepted = xr.create_sampling_rule(SamplingRule=bad)
    except ClientError as exc:
        err = exc.response["Error"]
        code = err.get("Code")
        assert code == "ValidationException", (
            f"6 sampling-rule attributes (max 5) must be refused as ValidationException, "
            f"got {code!r}: {err.get('Message')!r}"
        )
        # The service renders the map in its own fixed key order, not the request's.
        assert err.get("Message") == (
            "1 validation error detected: Value '{probe_key_5=probe_value_5, "
            "probe_key_4=probe_value_4, probe_key_3=probe_value_3, probe_key_2=probe_value_2, "
            "probe_key_1=probe_value_1, probe_key_0=probe_value_0}' at 'samplingRule.attributes' "
            "failed to satisfy constraint: Member must have length less than or equal to 5"
        ), f"the rejection must name the attributes length constraint, got {err!r}"
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        # Do not leak a rule the service should have refused.
        ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, bad_name))
        raise AssertionError(
            f"CreateSamplingRule accepted 6 attributes (modelled max 5): {accepted!r}"
        )

    # Effect absent: the refused rule was not created.
    records = _sampling_rule_records(xr)
    assert bad_name not in records, (
        f"refused rule {bad_name} must not appear in GetSamplingRules"
    )

    # Control: the legal 5-attribute rule is still there, unmodified.
    assert good_name in records, f"control rule {good_name} vanished: {sorted(records)!r}"
    assert records[good_name]["SamplingRule"]["Attributes"] == at_max, records[good_name]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
