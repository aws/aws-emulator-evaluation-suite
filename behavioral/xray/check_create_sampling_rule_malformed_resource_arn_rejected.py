"""create-sampling-rule-malformed-resource-arn-rejected."""
from __future__ import annotations

import datetime
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-sampling-rule-malformed-resource-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['xray']

ERR_INVALID_REQUEST = "InvalidRequestException"
_MALFORMED_ARN = "not-an-arn"


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _default_sampling_rule(name, **overrides):
    rule = {
        "RuleName": name,
        "ResourceARN": "*",
        # High priority number so a test rule never shadows another client's rule in the account.
        "Priority": random.randint(9000, 9899),
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
    """Every SamplingRuleRecord in the account, following NextToken (other rules can fill page one)."""
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A non-ARN SamplingRule.ResourceARN is refused with InvalidRequestException and stores nothing.
    The same rule with a well-formed concrete ARN is accepted, echoed, listed and served as a target.

    Reference: https://docs.aws.amazon.com/xray/latest/api/API_CreateSamplingRule.html
    """
    xr = ctx.client("xray")
    # X-Ray enforces ARN syntax only; any well-formed non-wildcard ARN is accepted.
    concrete_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:instance/i-0123456789abcdef0"

    # --- baseline, paginated ------------------------------------------------------------
    records_before = _sampling_rule_records(xr)
    bad_name = ctx.unique_name("sim2real-bh-xba-")
    good_name = ctx.unique_name("sim2real-bh-xok-")
    assert bad_name not in records_before and good_name not in records_before, (
        f"the freshly generated rule names already exist: "
        f"{sorted(set(records_before) & {bad_name, good_name})!r}"
    )

    # --- break exactly one thing: ResourceARN is not ARN-shaped -------------------------
    bad = _default_sampling_rule(bad_name, ResourceARN=_MALFORMED_ARN)
    try:
        accepted = xr.create_sampling_rule(SamplingRule=bad)
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == ERR_INVALID_REQUEST, (
            f"a sampling rule whose ResourceARN is not ARN-shaped must be refused with "
            f"{ERR_INVALID_REQUEST!r}; accepting it lets a client scope sampling by a string that "
            f"names no resource, and the rule then matches unpredictably: got "
            f"{err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == (
            f"Invalid resource ARN: {_MALFORMED_ARN}. Malformed ARN - doesn't start with 'arn:'"
        ), (
            f"the refusal must name the offending value and the syntax rule it broke, which is "
            f"what distinguishes it from a rejection of the rule as a whole: got "
            f"{err.get('Message')!r}"
        )
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, exc.response
    else:
        # Do not leak a rule the service should have refused. Cleanup is registered from THIS
        # response rather than from a lookup, which would lag the create.
        ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, bad_name))
        raise AssertionError(
            f"CreateSamplingRule accepted ResourceARN={_MALFORMED_ARN!r}: {accepted!r}"
        )

    # --- effect absent -------------------------------------------------------------------
    records_after = _sampling_rule_records(xr)
    assert bad_name not in records_after, (
        f"a refused CreateSamplingRule still stored the rule: "
        f"{sorted(set(records_after) - set(records_before))!r}"
    )
    assert len(records_after) == len(records_before), (
        f"the sampling rule count changed across a refused create: {len(records_before)} -> "
        f"{len(records_after)}"
    )

    # --- positive control: the identical body with a WELL-FORMED non-wildcard ARN --------
    good = _default_sampling_rule(good_name, ResourceARN=concrete_arn)
    good["Priority"] = bad["Priority"]
    good["FixedRate"] = bad["FixedRate"]
    good["ReservoirSize"] = bad["ReservoirSize"]
    created = xr.create_sampling_rule(
        SamplingRule=good, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["SamplingRuleRecord"]
    ctx.on_cleanup(lambda: _delete_rule_and_confirm(xr, good_name))
    assert created["SamplingRule"]["ResourceARN"] == concrete_arn, (
        f"the accepted rule must echo the concrete ARN it was created with, not normalise it to a "
        f"wildcard: {created!r}"
    )
    assert created["SamplingRule"]["RuleARN"], (
        f"an accepted rule must carry a RuleARN: {created!r}"
    )
    assert created["SamplingRule"]["FixedRate"] == bad["FixedRate"], (
        f"the control rule differs from the refused one in ResourceARN alone, so every other "
        f"field must round-trip unchanged: {created!r}"
    )

    listed = _poll_until(
        lambda: _sampling_rule_records(xr),
        lambda recs: good_name in recs,
        timeout_s=60,
        interval_s=2,
        description=f"the accepted rule {good_name} listed by GetSamplingRules",
    )
    assert listed[good_name]["SamplingRule"]["ResourceARN"] == concrete_arn, (
        f"the stored rule must hold the concrete ARN: {listed[good_name]!r}"
    )

    # --- positive control, data-plane leg: the accepted rule serves a target -------------
    resp = xr.get_sampling_targets(SamplingStatisticsDocuments=[{
        "RuleName": good_name,
        "ClientID": _hex(24),
        "Timestamp": datetime.datetime.now(datetime.timezone.utc),
        "RequestCount": 40,
        "SampledCount": 2,
        "BorrowCount": 0,
    }])
    assert resp.get("UnprocessedStatistics", []) == [], (
        f"the accepted rule did not process a statistics document, so acceptance did not make it "
        f"functional: {resp!r}"
    )
    targets = resp["SamplingTargetDocuments"]
    assert [t["RuleName"] for t in targets] == [good_name], (
        f"the accepted rule must be served as a sampling target -- a rule that exists but is never "
        f"served tells an instrumented client nothing: {resp!r}"
    )
    assert targets[0]["FixedRate"] == bad["FixedRate"], (
        f"the served target must carry the rule's own FixedRate, not a default: {targets[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
