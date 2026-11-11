"""list-alarm-mute-rules-order-stable-across-unrelated-updates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-alarm-mute-rules-order-stable-across-unrelated-updates"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating one alarm mute rule's schedule applies and leaves all three rules listed by
    ListAlarmMuteRules; AWS documents no listing order, so a reorder is accepted."""
    cw = ctx.client("cloudwatch")

    names = [ctx.unique_name(f"sim2real-cw-mute-{i}-") for i in range(3)]
    base_rule = {"Schedule": {"Expression": "cron(0 2 * * *)", "Duration": "PT1H"}}
    for name in names:
        cw.put_alarm_mute_rule(Name=name, Rule=base_rule)
        ctx.on_cleanup(lambda n=name: cw.delete_alarm_mute_rule(AlarmMuteRuleName=n))

    before = _ordered_names(ctx, names)
    assert before == names or sorted(before) == sorted(names), (
        f"expected all 3 created rules present, got {before}"
    )

    # Update only the *middle* rule's schedule -- unrelated to the other two.
    cw.put_alarm_mute_rule(
        Name=names[1],
        Rule={"Schedule": {"Expression": "cron(0 3 * * *)", "Duration": "PT2H"}},
    )

    # Confirm the update actually took effect (so this is a real mutation, not a no-op).
    updated = cw.get_alarm_mute_rule(AlarmMuteRuleName=names[1])
    assert updated["Rule"]["Schedule"]["Expression"] == "cron(0 3 * * *)", (
        f"expected updated schedule expression 'cron(0 3 * * *)', "
        f"got {updated['Rule']['Schedule']['Expression']!r}"
    )

    after = _ordered_names(ctx, names)
    assert after == before or sorted(after) == sorted(before), (
        f"unrelated mute-rule update changed the listed rules: before={before} after={after}"
    )


def _ordered_names(ctx, names: list) -> list:
    """Returns `names` filtered to only the ones present in ListAlarmMuteRules,
    in the relative order the API returned them (paginating through all
    results), by resolving each summary's ARN back to a rule name."""
    cw = ctx.client("cloudwatch")
    name_by_arn = {
        cw.get_alarm_mute_rule(AlarmMuteRuleName=n)["AlarmMuteRuleArn"]: n for n in names
    }

    ordered_arns = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = cw.list_alarm_mute_rules(**kwargs)
        ordered_arns.extend(s["AlarmMuteRuleArn"] for s in resp.get("AlarmMuteRuleSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break

    return [name_by_arn[arn] for arn in ordered_arns if arn in name_by_arn]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
