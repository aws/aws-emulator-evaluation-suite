"""enable-insight-rules-limit-exceeded-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-insight-rules-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]

# The account quota "Number of Contributor Insights rules" (default 100) counts every rule
# object, ENABLED or DISABLED: PutInsightRule of a new rule at the limit fails with
# LimitExceededException (TOTAL_RULES_EXCEEDED), while EnableInsightRules on an existing
# DISABLED rule succeeds, because the quota gates creation, not a state change.
_RULE_QUOTA = 100
# Every rule this check creates (the DISABLED probe and the ENABLED fillers) is
# named under this prefix, and it is the ONLY prefix the stale-rule sweep in
# run() is allowed to delete -- see the comment there.
_OWN_PREFIX = "sim2real-behav-air-"
_RULE_DEF = json.dumps(
    {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "LogGroupNames": ["sim2real-behav-nonexistent-lg"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.ip"], "Filters": []},
        "AggregateOn": "Count",
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """At the account's total Contributor Insights rule quota, PutInsightRule for a new
    rule is rejected with LimitExceededException, but EnableInsightRules on a rule that
    already exists succeeds -- the quota gates object creation, not a state change."""
    cw = ctx.client("cloudwatch")
    created: list[str] = []

    def _cleanup():
        # DeleteInsightRules succeeds with empty Failures for a missing rule, so any error raises.
        for chunk in _chunks(created, 20):
            delay = 0.5
            for attempt in range(4):
                try:
                    resp = cw.delete_insight_rules(RuleNames=chunk)
                    break
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    if code in {"Throttling", "TooManyRequestsException"} and attempt < 3:
                        time.sleep(delay)
                        delay *= 2
                        continue
                    raise
            if resp.get("Failures"):
                raise AssertionError(f"DeleteInsightRules left rules behind: {resp['Failures']}")

    ctx.on_cleanup(_cleanup)

    # Reclaim rules a previous run of THIS check left behind (they consume the total-rule
    # quota it needs headroom under). The sweep is scoped to this check's own name prefix so it
    # never deletes another check's live rules; DeleteInsightRules takes at most 20 names.
    stale = [
        r["Name"] for r in _list_all_insight_rules(cw) if r["Name"].startswith(_OWN_PREFIX)
    ]
    for chunk in _chunks(stale, 20):
        delay = 0.5
        for attempt in range(4):
            try:
                cw.delete_insight_rules(RuleNames=chunk)
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code in {"Throttling", "TooManyRequestsException"} and attempt < 3:
                    time.sleep(delay)
                    delay *= 2
                    continue
                # Give up on this chunk (e.g. rule already gone, or a
                # non-throttling error) rather than crashing this best-effort
                # reclaim sweep.
                break

    # DeleteInsightRules is only eventually consistent against the account-wide total-rule
    # quota, so poll for the quota to clear before creating the probe rule.
    _poll_until(lambda: len(_list_all_insight_rules(cw)) < _RULE_QUOTA, timeout=60.0, interval=3.0)

    # Create the DISABLED probe rule first, while the account still has headroom under the
    # total-rule quota; it needs only a free slot, not a reserved one. LimitExceeded on this
    # create is retried with backoff.
    extra_name = ctx.unique_name(f"{_OWN_PREFIX}extra-")
    delay = 2.0
    _PROBE_ATTEMPTS = 8
    for attempt in range(_PROBE_ATTEMPTS):
        try:
            _put_rule_with_retry(cw, extra_name, "DISABLED")
            break
        except ClientError as e:
            if (
                e.response["Error"]["Code"] in {"LimitExceededException", "LimitExceededFault"}
                and attempt < _PROBE_ATTEMPTS - 1
            ):
                # Wait and retry rather than sweeping again: the stale sweep above runs once
                # and is limited to this check's own prefix, so it never deletes rules that
                # other workloads in the account are still using.
                time.sleep(delay)
                delay = min(delay * 2, 20.0)
                continue
            raise
    created.append(extra_name)

    # Now fill the remaining quota with ENABLED rules so that the account
    # ends up at (or effectively at) the total-rule limit, leaving no
    # headroom for the EnableInsightRules call under test to consume. Account
    # for rules that already exist (e.g. leftovers from other runs, or the
    # probe rule just created above) rather than assuming a clean slate.
    # Count *all* rules regardless of state, since the account-wide "total
    # rule limit" quota (confirmed via real AWS's PutInsightRule error text)
    # counts ENABLED and DISABLED rules alike.
    existing_total = len(_list_all_insight_rules(cw))
    needed = max(0, _RULE_QUOTA - existing_total)

    for i in range(needed):
        name = ctx.unique_name(f"{_OWN_PREFIX}{i}-")
        try:
            _put_rule_with_retry(cw, name, "ENABLED")
        except ClientError as e:
            if e.response["Error"]["Code"] in {"LimitExceededException", "LimitExceededFault"}:
                # The rule count observed via describe_insight_rules is only
                # eventually consistent and can race with other activity in
                # the account (including other concurrently-running checks),
                # so the quota boundary may be reached sooner than this
                # precomputed `needed` count predicted. That is fine -- it
                # just means the total-rule quota is already saturated, which
                # is exactly the precondition this check needs.
                break
            raise
        created.append(name)

    # Positive control: the account is genuinely saturated. Creating one more
    # *new* rule object is rejected -- confirmed via real AWS's own
    # PutInsightRule response text (TOTAL_RULES_EXCEEDED). Without this leg, a
    # target that never enforces the quota at all would still pass the
    # EnableInsightRules assertion below for the wrong reason.
    control_name = ctx.unique_name(f"{_OWN_PREFIX}control-")
    # Tracked before the call, so a target that wrongly accepts it still gets cleaned up.
    created.append(control_name)
    control_code, control_message = _error(
        lambda: cw.put_insight_rule(RuleName=control_name, RuleDefinition=_RULE_DEF, RuleState="ENABLED")
    )
    assert control_code == "LimitExceededException", control_code
    assert control_message == f"TOTAL_RULES_EXCEEDED: Put would exceed the total rule limit of {_RULE_QUOTA}.", (
        f"unexpected PutInsightRule quota message {control_message!r}"
    )

    # The boundary-crossing operation under test: flipping the already-existing
    # DISABLED probe rule to ENABLED while the account is at the total-rule
    # quota. This succeeds on real AWS -- the quota counted the probe rule the
    # moment PutInsightRule created it (DISABLED or not), so enabling it changes
    # no count and crosses no boundary. A target that instead rejects this call
    # is over-applying the creation quota to a state transition.
    cw.enable_insight_rules(RuleNames=[extra_name])

    # Independent read at the destination, through a different operation than
    # the one that mutated: the probe rule is now ENABLED.
    refreshed = {r["Name"]: r for r in _list_all_insight_rules(cw)}
    assert extra_name in refreshed, f"probe rule {extra_name} missing from DescribeInsightRules after EnableInsightRules"
    assert refreshed[extra_name]["State"] == "ENABLED", (
        f"expected {extra_name} to be ENABLED after EnableInsightRules, got {refreshed[extra_name]['State']!r}"
    )


# ===== helpers =====
def _poll_until(predicate, timeout=60.0, interval=2.0):
    """Bounded poll: call predicate() until truthy or timeout elapses.

    Returns True if predicate became truthy before the timeout, False
    otherwise (never raises on timeout -- callers fall through to their own
    bounded-retry logic either way).
    """
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so an over-permissive target's acceptance is reported as such rather than
    as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected PutInsightRule to be rejected once the rule quota is full, got {result!r}")


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _list_all_insight_rules(cw):
    rules = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.describe_insight_rules(**kwargs)
        rules.extend(resp.get("InsightRules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return rules


def _put_rule_with_retry(cw, name, state, attempts=4):
    delay = 0.5
    for attempt in range(attempts):
        try:
            cw.put_insight_rule(RuleName=name, RuleDefinition=_RULE_DEF, RuleState=state)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in {"Throttling", "TooManyRequestsException"} and attempt < attempts - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
