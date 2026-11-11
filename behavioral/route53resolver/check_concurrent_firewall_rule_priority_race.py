"""concurrent-firewall-rule-priority-race."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-firewall-rule-priority-race"
GROUP = 'concurrency'
SERVICES = ['route53resolver']

def _run_concurrent(fns, timeout_s=60):
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _cap(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 -- captured for the caller to assert on
            results[idx] = exc
        resolved.add(idx)

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        f2i = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(f2i, timeout=timeout_s):
                _cap(fut, f2i[fut])
        except concurrent.futures.TimeoutError as te:
            for fut, idx in f2i.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _cap(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = te
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _concurrent_error_messages(results):
    return [
        _without_trace_id(r.response.get("Error", {}).get("Message"))
        for r in results
        if isinstance(r, ClientError)
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When N racers concurrently create rules at the SAME priority in one group, exactly one wins."""
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    n = 5
    domain_list_ids = []
    for _ in range(n):
        dl_id = r53.create_firewall_domain_list(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-fdl-")
        )["FirewallDomainList"]["Id"]
        ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
        domain_list_ids.append(dl_id)

    shared_priority = 999
    names = [ctx.unique_name("sim2real-behav-fr-race-") for _ in range(n)]

    def make_racer(idx):
        def racer():
            return r53.create_firewall_rule(
                CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
                FirewallRuleGroupId=group_id,
                FirewallDomainListId=domain_list_ids[idx],
                Priority=shared_priority,
                Action="ALLOW",
                Name=names[idx],
            )

        return racer

    results = _run_concurrent([make_racer(i) for i in range(n)])
    n_success = _concurrent_successes(results)
    error_codes = _concurrent_error_codes(results)

    # Track whichever rule(s) actually got created for cleanup BEFORE asserting,
    # so a surprising outcome still leaves the account clean.
    rules = r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    created_names = {r["Name"] for r in rules if r["Name"] in names}
    for r in rules:
        if r["Name"] in names:
            dl_for_name = domain_list_ids[names.index(r["Name"])]
            ctx.on_cleanup(lambda g=group_id, d=dl_for_name: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d))
    assert n_success == 1, (
        f"expected exactly one racer to win the priority slot, got {n_success}: "
        f"errors={error_codes}"
    )
    assert len(error_codes) == n - 1, f"expected {n - 1} losers, got {error_codes}"
    for code in error_codes:
        assert code == "ValidationException", (
            f"expected ValidationException for a losing racer, got {code}"
        )
    expected = (
        "[RSLVR-02203] The DNS Firewall rule group already has a rule associated with the same "
        f'priority: "{group_id}". Provide another priority.'
    )
    for message in _concurrent_error_messages(results):
        assert message == expected, f"expected message {expected!r} for a losing racer, got {message!r}"

    # Terminal assertion is an independent read (ListFirewallRules) at the destination,
    # not the mutating calls' own responses: the winner the racers' results claim must be
    # exactly -- and the only -- rule the group reports at the shared priority.
    winner_idx = next(i for i, r in enumerate(results) if not isinstance(r, BaseException))
    assert created_names == {names[winner_idx]}, (
        f"ListFirewallRules reports {created_names} at priority {shared_priority}, "
        f"but the racer results claim the winner is {names[winner_idx]!r}"
    )
    winner_rule = next(r for r in rules if r["Name"] == names[winner_idx])
    assert winner_rule["Priority"] == shared_priority, (
        f"persisted winner has priority {winner_rule['Priority']}, expected {shared_priority}"
    )


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
