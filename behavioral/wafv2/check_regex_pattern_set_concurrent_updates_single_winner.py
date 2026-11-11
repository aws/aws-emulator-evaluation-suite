"""regex-pattern-set-concurrent-updates-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regex-pattern-set-concurrent-updates-single-winner"
GROUP = "concurrency"
SERVICES = ["wafv2"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


#: WAFNonexistentItemException's message for a deleted regex pattern set.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
#: WAFOptimisticLockException's message for a write with a consumed LockToken.
LOCK_MESSAGE = (
    "AWS WAF couldn’t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two UpdateRegexPatternSet calls on one LockToken: exactly one wins and persists, the other
    fails WAFOptimisticLockException; after deletion, both a read and a mutation see it gone."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-regex-")

    created = wafv2.create_regex_pattern_set(
        Name=name,
        Scope=scope,
        RegularExpressionList=[{"RegexString": "seed-.*"}],
        Tags=_TAGS_KV,
    )["Summary"]
    set_id = created["Id"]

    def _get():
        return wafv2.get_regex_pattern_set(Name=name, Scope=scope, Id=set_id)

    def _cleanup():
        try:
            current = _get()
        except ClientError as e:
            if e.response["Error"]["Code"] == "WAFNonexistentItemException":
                return
            raise
        wafv2.delete_regex_pattern_set(Name=name, Scope=scope, Id=set_id, LockToken=current["LockToken"])

    ctx.on_cleanup(_cleanup)

    lock_token = created["LockToken"]

    def _racer(pattern):
        try:
            wafv2.update_regex_pattern_set(
                Name=name,
                Scope=scope,
                Id=set_id,
                RegularExpressionList=[{"RegexString": pattern}],
                LockToken=lock_token,
            )
            return ("ok", pattern, None, None)
        except ClientError as e:
            return ("error", pattern, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    candidates = ["racer-b-.*", "racer-c-.*"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_racer, candidates))

    outcomes = [r[0] for r in results]
    assert outcomes.count("ok") == 1, f"expected exactly one winner, got {results}"
    assert outcomes.count("error") == 1, f"expected exactly one loser, got {results}"

    loser = next(r for r in results if r[0] == "error")
    assert loser[2] == "WAFOptimisticLockException", (
        f"expected the losing racer to be rejected with WAFOptimisticLockException, got {loser[2]!r}"
    )
    assert loser[3] == LOCK_MESSAGE, loser[3]

    winner_pattern = next(r[1] for r in results if r[0] == "ok")
    final = _get()
    assert final["RegexPatternSet"]["RegularExpressionList"] == [{"RegexString": winner_pattern}], (
        f"expected the persisted pattern to be the winner's {winner_pattern!r}, "
        f"got {final['RegexPatternSet']['RegularExpressionList']!r}"
    )

    wafv2.delete_regex_pattern_set(Name=name, Scope=scope, Id=set_id, LockToken=final["LockToken"])

    gone_code, gone_message = _error(_get)
    assert gone_code == "WAFNonexistentItemException", (
        f"expected a deleted regex pattern set to read back as WAFNonexistentItemException, got {gone_code!r}"
    )
    assert gone_message == NONEXISTENT_MESSAGE, gone_message

    mutate_code, mutate_message = _error(
        lambda: wafv2.update_regex_pattern_set(
            Name=name,
            Scope=scope,
            Id=set_id,
            RegularExpressionList=[{"RegexString": "post-delete-.*"}],
            LockToken=final["LockToken"],
        )
    )
    assert mutate_code == "WAFNonexistentItemException", (
        f"expected UpdateRegexPatternSet on a deleted set to fail with WAFNonexistentItemException, "
        f"got {mutate_code!r}"
    )
    assert mutate_message == NONEXISTENT_MESSAGE, mutate_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
