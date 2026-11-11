"""concurrent-receipt-rule-set-create-exactly-one-wins."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-receipt-rule-set-create-exactly-one-wins"
GROUP = 'receipt-rules'
SERVICES = ['ses']

def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; skip elsewhere."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


def _track_receipt_rule_set(ctx, ses, name):
    """Register teardown for a receipt rule set. This check never activates the set, so the
    account's active rule set is left exactly as it was found."""
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=name))
    return name


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_errors(results):
    """(code, message) for every loser; a non-ClientError loser reports its type name."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            err = r.response.get('Error', {})
            errors.append((err.get('Code'), err.get('Message')))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateReceiptRuleSet on one name serializes to a single winner; losers get AlreadyExists or Throttling, and the set exists exactly once.

    CreateReceiptRuleSet has a very small per-second quota, so a loser may be shed
    with Throttling instead of reaching AlreadyExists — both are legitimate loser outcomes.
    """
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    name = ctx.unique_name("sim2real-behav-ruleset-race-")

    def create():
        return ses.create_receipt_rule_set(RuleSetName=name)

    results = _run_concurrent([create for _ in range(3)], timeout_s=90)
    _track_receipt_rule_set(ctx, ses, name)

    successes = _concurrent_successes(results)
    errors = _concurrent_errors(results)
    assert successes == 1, f"expected exactly 1 winner, got {successes} (errors={errors})"
    assert len(errors) == 2, f"expected 2 losers, got {errors}"
    for code, message in errors:
        if code == "Throttling":
            # message varies: a shed request is refused by the front door before the rule-set
            # store is consulted, so no stable message is known; only the code is asserted.
            continue
        assert code == "AlreadyExists", f"unexpected loser code: {errors}"
        assert message == f"Rule set already exists: {name}", (
            f"a losing create must name the rule set that already exists, got {message!r}"
        )

    listed = [rs["Name"] for rs in ses.list_receipt_rule_sets()["RuleSets"]]
    assert listed.count(name) == 1, f"expected exactly one rule set named {name}, got {listed.count(name)}"
    assert ses.describe_receipt_rule_set(RuleSetName=name)["Rules"] == [], "winning rule set should be empty"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
