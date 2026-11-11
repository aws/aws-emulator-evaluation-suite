"""custom-action-attachment-criteria-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-action-attachment-criteria-roundtrip"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomAction persists Attachments (ButtonText/NotificationType/Criteria)
    exactly, and GetCustomAction returns the same structured data back."""
    chatbot = ctx.client("chatbot")
    name = ctx.unique_name("sim2realattach").replace("-", "")[:64]
    attachments = [
        {
            "NotificationType": "CloudWatchAlarmStateChange",
            "ButtonText": "Run Diagnostics",
            "Criteria": [
                {"Operator": "EQUALS", "VariableName": "AlarmName", "Value": "sim2real-alarm"}
            ],
        }
    ]

    created = chatbot.create_custom_action(
        ActionName=name,
        Definition={"CommandText": "aws cloudwatch describe-alarms --alarm-names $AlarmName"},
        Attachments=attachments,
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )
    arn = created["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn))

    got = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert len(got["Attachments"]) == 1, f"expected 1 attachment, got {got['Attachments']!r}"
    attachment = got["Attachments"][0]
    assert attachment["ButtonText"] == "Run Diagnostics", (
        f"expected ButtonText='Run Diagnostics', got {attachment['ButtonText']!r}"
    )
    assert attachment["NotificationType"] == "CloudWatchAlarmStateChange", (
        f"expected NotificationType='CloudWatchAlarmStateChange', got {attachment['NotificationType']!r}"
    )
    assert len(attachment["Criteria"]) == 1, f"expected 1 criterion, got {attachment['Criteria']!r}"
    criterion = attachment["Criteria"][0]
    assert criterion["Operator"] == "EQUALS", f"expected Operator='EQUALS', got {criterion['Operator']!r}"
    assert criterion["VariableName"] == "AlarmName", (
        f"expected VariableName='AlarmName', got {criterion['VariableName']!r}"
    )
    assert criterion["Value"] == "sim2real-alarm", (
        f"expected Value='sim2real-alarm', got {criterion['Value']!r}"
    )


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
