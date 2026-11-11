"""metric-extraction-policy-overlapping-selection-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-extraction-policy-overlapping-selection-rejected"
GROUP = "account-policy"
SERVICES = ["logs"]

_POLICY_TYPE = "METRIC_EXTRACTION_POLICY"
_DOC = json.dumps({"EmbeddedMetricFormat": {"Status": "Disabled"}})


_NO_ERROR = "<no error raised: the call succeeded>"


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """A METRIC_EXTRACTION_POLICY whose selection overlaps another's (same group or covering prefix)
    is rejected with InvalidParameterException and not stored; disjoint criteria, widening a
    policy's own criteria, and the rejected criteria after deleting the first policy all succeed."""
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-ovl-")
    first = ctx.unique_name("sim2real-behav-mep-a-")
    same = ctx.unique_name("sim2real-behav-mep-b-")
    prefix = ctx.unique_name("sim2real-behav-mep-c-")
    disjoint = ctx.unique_name("sim2real-behav-mep-d-")

    def _put(name, criteria):
        return logs.put_account_policy(
            policyName=name, policyType=_POLICY_TYPE, policyDocument=_DOC, scope="ALL",
            selectionCriteria=criteria,
        )

    def _stored(name):
        return logs.describe_account_policies(
            policyType=_POLICY_TYPE, policyName=name)["accountPolicies"]

    def _net(name):
        ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_account_policy(
            policyName=name, policyType=_POLICY_TYPE)))

    _put(first, f'LogGroupName IN ["{group}"]')
    _net(first)
    assert [p["selectionCriteria"] for p in _stored(first)] == [f'LogGroupName IN ["{group}"]'], (
        f"the first policy was not stored as written: {_stored(first)!r}"
    )

    # Nets registered BEFORE the calls expected to fail: an emulator that wrongly accepts one
    # has created account-scoped state.
    for name, criteria, label in (
        (same, f'LogGroupName IN ["{group}"]', "the same log group name"),
        (prefix, f'LogGroupNamePrefix IN ["{group}"]', "a prefix covering that group"),
    ):
        _net(name)
        code, code_msg = _error_code(lambda name=name, criteria=criteria: _put(name, criteria))
        assert code == "InvalidParameterException", (
            f"a second METRIC_EXTRACTION_POLICY selecting {label} ({criteria!r}) returned "
            f"{code!r}; it overlaps policy {first!r} and must be rejected with "
            f"InvalidParameterException"
        )
        expected = f"SelectionCriteria is overlapping with an existing policy with policy name: {first}"
        assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"
        assert _stored(name) == [], (
            f"the rejected overlapping policy {name!r} was stored anyway: {_stored(name)!r}"
        )

    # Positive control: disjoint criteria are accepted alongside the first policy.
    _net(disjoint)
    _put(disjoint, f'LogGroupName IN ["{group}-other"]')
    assert len(_stored(disjoint)) == 1, f"the disjoint policy was not stored: {_stored(disjoint)!r}"
    logs.delete_account_policy(policyName=disjoint, policyType=_POLICY_TYPE)

    # The overlap rule is keyed on policy identity: updating the first policy to a SUPERSET of
    # its own criteria is accepted.
    widened = f'LogGroupName IN ["{group}","{group}-b"]'
    _put(first, widened)
    assert [p["selectionCriteria"] for p in _stored(first)] == [widened], (
        f"re-putting {first!r} with a superset of its own criteria did not replace them: "
        f"{_stored(first)!r}"
    )

    # Transition: once the conflicting policy is gone, the rejected criteria are acceptable.
    logs.delete_account_policy(policyName=first, policyType=_POLICY_TYPE)
    assert _stored(first) == [], f"DeleteAccountPolicy left {_stored(first)!r}"
    _put(same, f'LogGroupName IN ["{group}"]')
    assert [p["selectionCriteria"] for p in _stored(same)] == [f'LogGroupName IN ["{group}"]'], (
        f"after deleting {first!r} the previously overlapping policy was not accepted and "
        f"stored: {_stored(same)!r}"
    )
    logs.delete_account_policy(policyName=same, policyType=_POLICY_TYPE)
    assert _stored(same) == [], f"DeleteAccountPolicy left {_stored(same)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
