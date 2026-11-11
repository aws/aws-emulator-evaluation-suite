"""get-alarm-mute-rule-after-delete-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-alarm-mute-rule-after-delete-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteAlarmMuteRule, GetAlarmMuteRule on the rule fails with ResourceNotFoundException
    and an empty message and ListAlarmMuteRules omits its ARN, while a kept rule still resolves
    with its Name and Description and stays listed."""
    cw = ctx.client("cloudwatch")
    name_deleted = ctx.unique_name("sim2real-mute-del-")
    name_kept = ctx.unique_name("sim2real-mute-keep-")

    rule = {"Schedule": {"Expression": "cron(0 4 * * ?)", "Duration": "PT1H", "Timezone": "UTC"}}
    cw.put_alarm_mute_rule(Name=name_deleted, Description="to-be-deleted", Rule=rule)
    # A second DeleteAlarmMuteRule is a no-op success, so this cleanup also covers a failure
    # between creation and the explicit delete below.
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=name_deleted))
    cw.put_alarm_mute_rule(Name=name_kept, Description="kept", Rule=rule)
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=name_kept))

    # AlarmMuteRuleSummary (the ListAlarmMuteRules item shape) carries only the ARN,
    # not the Name, so capture ARNs via GetAlarmMuteRule before deleting.
    deleted_arn = cw.get_alarm_mute_rule(AlarmMuteRuleName=name_deleted)["AlarmMuteRuleArn"]
    kept_arn = cw.get_alarm_mute_rule(AlarmMuteRuleName=name_kept)["AlarmMuteRuleArn"]

    cw.delete_alarm_mute_rule(AlarmMuteRuleName=name_deleted)

    code, message = _error(lambda: cw.get_alarm_mute_rule(AlarmMuteRuleName=name_deleted))
    assert code == "ResourceNotFoundException", (
        f"expected GetAlarmMuteRule on a deleted rule to reject with ResourceNotFoundException, got {code!r}"
    )
    # GetAlarmMuteRule answers not-found with an empty message.
    assert message == "", f"unexpected GetAlarmMuteRule message {message!r}"

    # Effect confirmed absent: the deleted rule's ARN no longer appears in the list either.
    arns = {
        entry["AlarmMuteRuleArn"]
        for page in cw.get_paginator("list_alarm_mute_rules").paginate()
        for entry in page.get("AlarmMuteRuleSummaries", [])
    }
    assert deleted_arn not in arns, (
        f"expected deleted rule ARN {deleted_arn!r} to be absent from ListAlarmMuteRules, but it was present"
    )

    # Positive control: the sibling rule that was never deleted still resolves fine.
    kept = cw.get_alarm_mute_rule(AlarmMuteRuleName=name_kept)
    assert kept["Name"] == name_kept, f"expected kept rule Name {name_kept!r}, got {kept['Name']!r}"
    assert kept["Description"] == "kept", f"expected kept rule Description 'kept', got {kept['Description']!r}"
    assert kept_arn in arns, (
        f"expected kept rule ARN {kept_arn!r} to still be present in ListAlarmMuteRules, but it was absent"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, so
    a target that accepts a call AWS rejects is never reported as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
