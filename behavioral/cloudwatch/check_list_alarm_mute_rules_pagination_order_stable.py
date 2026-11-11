"""list-alarm-mute-rules-pagination-order-stable."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone as _dt_timezone

from behavioral_harness import tags

CHECK = "list-alarm-mute-rules-pagination-order-stable"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginated ListAlarmMuteRules pages preserve a stable, consistent ordering of rules across
    NextToken continuations -- re-paginating with a different page size yields the same overall
    order for the same underlying rules, and nothing is duplicated or dropped.
    """
    cw = ctx.client("cloudwatch")
    # A recurring cron expression such as "cron(0 3 * * ? *)" is rejected server-side with
    # "The Alarm Mute Rule Schedule expression provided is not valid" -- a well-formed one-time
    # at() expression in the future is accepted instead.
    future = (datetime.now(_dt_timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
    rule = {"Schedule": {"Expression": f"at({future})", "Duration": "PT1H"}}
    names = [ctx.unique_name(f"sim2real-behav-mute-{i}-") for i in range(6)]
    for name in names:
        cw.put_alarm_mute_rule(Name=name, Rule=rule, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda n=name: cw.delete_alarm_mute_rule(AlarmMuteRuleName=n))

    def _list_all_arns(page_size: int) -> list[str]:
        collected: list[str] = []
        token = None
        seen_tokens: set[str] = set()
        while True:
            kwargs = {"MaxRecords": page_size}
            if token:
                kwargs["NextToken"] = token
            resp = cw.list_alarm_mute_rules(**kwargs)
            # Real CloudWatch's AlarmMuteRuleSummary (the shape returned by
            # ListAlarmMuteRules) does not include a "Name" field at all -- only
            # AlarmMuteRuleArn, ExpireDate, Status, MuteType, and LastUpdatedTimestamp.
            # Identify each summary's rule by the rule name being embedded in its ARN.
            collected.extend(s["AlarmMuteRuleArn"] for s in resp["AlarmMuteRuleSummaries"])
            token = resp.get("NextToken")
            if not token:
                break
            assert token not in seen_tokens, "pagination looped: NextToken repeated"
            seen_tokens.add(token)
        return collected

    def _name_for_arn(arn: str) -> str | None:
        for n in names:
            if n in arn:
                return n
        return None

    def _names_from_arns(arns: list[str]) -> list[str]:
        result = []
        for arn in arns:
            name = _name_for_arn(arn)
            if name is not None:
                result.append(name)
        return result

    full_small_page = _names_from_arns(_list_all_arns(2))
    full_large_page = _names_from_arns(_list_all_arns(100))

    assert sorted(full_small_page) == sorted(names), "not all created mute rules were listed with small pages"
    assert sorted(full_large_page) == sorted(names), "not all created mute rules were listed with large pages"
    assert len(full_small_page) == len(set(full_small_page)), "small-page listing contained duplicates"
    assert full_small_page == full_large_page, (
        f"pagination with different page sizes produced a different relative order: "
        f"{full_small_page} vs {full_large_page}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
