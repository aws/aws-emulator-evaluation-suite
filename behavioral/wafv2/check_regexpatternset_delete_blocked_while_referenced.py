"""regexpatternset-delete-blocked-while-referenced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regexpatternset-delete-blocked-while-referenced"
GROUP = "state-machine"
SERVICES = ["wafv2"]

#: WAFNonexistentItemException's message for a deleted regex pattern set.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
#: WAFAssociatedItemException's message for a delete blocked by a reference.
ASSOCIATED_MESSAGE = (
    "AWS WAF couldn’t perform the operation because your resource is being used by another "
    "resource or it’s associated with another resource."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRegexPatternSet is rejected with WAFAssociatedItemException while a RuleGroup
    references the set, and the set survives; once the reference is removed the identical
    delete succeeds (positive control)."""
    wafv2 = ctx.client("wafv2")

    regex_name = ctx.unique_name("sim2real-behav-regex-")
    regex_summary = wafv2.create_regex_pattern_set(
        Name=regex_name,
        Scope="REGIONAL",
        RegularExpressionList=[{"RegexString": "bad-[0-9]+"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )["Summary"]
    regex_arn = regex_summary["ARN"]
    regex_id = regex_summary["Id"]
    ctx.on_cleanup(lambda: _delete_locked(wafv2, "regex_pattern_set", regex_name, regex_id))

    rg_name = ctx.unique_name("sim2real-behav-rg-")

    def _create_rule_group():
        return wafv2.create_rule_group(
            Name=rg_name,
            Scope="REGIONAL",
            Capacity=50,
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": rg_name,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
            Rules=[
                {
                    "Name": "regex-rule",
                    "Priority": 0,
                    "Statement": {
                        "RegexPatternSetReferenceStatement": {
                            "ARN": regex_arn,
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": False,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "regex-rule",
                    },
                }
            ],
        )["Summary"]

    # A freshly created regex pattern set can briefly be WAFUnavailableEntityException
    # when referenced by a new RuleGroup before it propagates (documented "Temporary
    # inconsistencies during updates" behavior) - retry until it's referenceable.
    rg_summary = _retry_on_unavailable(_create_rule_group, timeout_s=60.0)
    rg_id = rg_summary["Id"]
    ctx.on_cleanup(lambda: _delete_locked(wafv2, "rule_group", rg_name, rg_id))

    lock_token = wafv2.get_regex_pattern_set(Name=regex_name, Scope="REGIONAL", Id=regex_id)["LockToken"]
    code, message = _error(
        lambda: wafv2.delete_regex_pattern_set(
            Name=regex_name, Scope="REGIONAL", Id=regex_id, LockToken=lock_token
        )
    )
    assert code == "WAFAssociatedItemException", f"expected WAFAssociatedItemException, got {code}"
    assert message == ASSOCIATED_MESSAGE, message

    # the rejected delete must not have removed the regex pattern set
    wafv2.get_regex_pattern_set(Name=regex_name, Scope="REGIONAL", Id=regex_id)

    # positive control: remove the reference, then the identical delete succeeds
    _delete_locked(wafv2, "rule_group", rg_name, rg_id)
    lock_token = wafv2.get_regex_pattern_set(Name=regex_name, Scope="REGIONAL", Id=regex_id)["LockToken"]
    wafv2.delete_regex_pattern_set(Name=regex_name, Scope="REGIONAL", Id=regex_id, LockToken=lock_token)
    dead_read_code, dead_read_message = _error(
        lambda: wafv2.get_regex_pattern_set(Name=regex_name, Scope="REGIONAL", Id=regex_id)
    )
    assert dead_read_code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException reading a deleted set, got {dead_read_code}"
    )
    assert dead_read_message == NONEXISTENT_MESSAGE, dead_read_message

    # a mutation on the now-dead id must also fail, not just a read
    dead_delete_code, dead_delete_message = _error(
        lambda: wafv2.delete_regex_pattern_set(
            Name=regex_name, Scope="REGIONAL", Id=regex_id, LockToken=lock_token
        )
    )
    assert dead_delete_code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException deleting an already-deleted set, got {dead_delete_code}"
    )
    assert dead_delete_message == NONEXISTENT_MESSAGE, dead_delete_message


# ===== helpers =====

def _retry_on_unavailable(fn, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "WAFUnavailableEntityException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded past WAFUnavailableEntityException: {last_err}")


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_locked(wafv2, kind, name, id_):
    """Refresh the LockToken then delete; gone is success, a reference still being
    released is retried every 2 s for up to 25 s, anything else raises."""
    getter = getattr(wafv2, f"get_{kind}")
    deleter = getattr(wafv2, f"delete_{kind}")
    deadline = time.monotonic() + 25.0
    while True:
        try:
            lock_token = getter(Name=name, Scope="REGIONAL", Id=id_)["LockToken"]
            deleter(Name=name, Scope="REGIONAL", Id=id_, LockToken=lock_token)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "WAFNonexistentItemException":
                return
            if code not in (
                "WAFAssociatedItemException", "WAFOptimisticLockException", "WAFUnavailableEntityException"
            ) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
