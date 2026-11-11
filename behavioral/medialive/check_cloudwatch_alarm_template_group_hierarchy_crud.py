"""cloudwatch-alarm-template-group-hierarchy-crud."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudwatch-alarm-template-group-hierarchy-crud"
GROUP = "resource-lifecycle"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudWatch alarm template created in a group reports that GroupId and Threshold 80.0, reads back
    Threshold 95.0 after an update, and after deletion Get and Update on the template, then on the
    deleted group, fail NotFoundException with no message."""
    medialive = ctx.client("medialive")
    group = medialive.create_cloud_watch_alarm_template_group(
        Name=ctx.unique_name("sim2real-medialive-cwgrp-"), Tags={"sim2real": CHECK}
    )
    group_id = group["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_cloud_watch_alarm_template_group(Identifier=group_id)))

    template_name = ctx.unique_name("sim2real-medialive-cwtpl-")
    template = medialive.create_cloud_watch_alarm_template(
        Name=template_name,
        GroupIdentifier=group_id,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="ActiveAlerts",
        Period=300,
        Statistic="Average",
        TargetResourceType="MEDIALIVE_CHANNEL",
        Threshold=80.0,
        TreatMissingData="notBreaching",
        Tags={"sim2real": CHECK},
    )
    template_id = template["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_cloud_watch_alarm_template(Identifier=template_id)))
    assert template["GroupId"] == group_id, f"expected template GroupId {group_id}, got {template['GroupId']}"
    assert template["Threshold"] == 80.0, f"expected initial Threshold 80.0, got {template['Threshold']}"

    medialive.update_cloud_watch_alarm_template(Identifier=template_id, Threshold=95.0)
    fetched = medialive.get_cloud_watch_alarm_template(Identifier=template_id)
    assert fetched["Threshold"] == 95.0, f"expected updated Threshold 95.0, got {fetched['Threshold']}"
    assert fetched["Name"] == template_name, f"expected Name {template_name}, got {fetched['Name']}"

    medialive.delete_cloud_watch_alarm_template(Identifier=template_id)
    # AWS answers these NotFoundExceptions with a null message, so the exact message is None.
    code, message = _client_error(
        lambda: medialive.get_cloud_watch_alarm_template(Identifier=template_id), "GetCloudWatchAlarmTemplate after delete"
    )
    assert code == "NotFoundException", f"expected NotFoundException reading deleted template, got {code}"
    assert message is None, f"expected no message reading deleted template, got {message!r}"
    update_code, update_message = _client_error(
        lambda: medialive.update_cloud_watch_alarm_template(Identifier=template_id, Threshold=50.0),
        "UpdateCloudWatchAlarmTemplate after delete",
    )
    assert update_code == "NotFoundException", f"expected NotFoundException updating deleted template, got {update_code}"
    assert update_message is None, f"expected no message updating deleted template, got {update_message!r}"

    # The group is empty, so deleting it succeeds.
    medialive.delete_cloud_watch_alarm_template_group(Identifier=group_id)
    group_code, group_message = _client_error(
        lambda: medialive.get_cloud_watch_alarm_template_group(Identifier=group_id),
        "GetCloudWatchAlarmTemplateGroup after delete",
    )
    assert group_code == "NotFoundException", f"expected NotFoundException reading deleted group, got {group_code}"
    assert group_message is None, f"expected no message reading deleted group, got {group_message!r}"
    group_update_code, group_update_message = _client_error(
        lambda: medialive.update_cloud_watch_alarm_template_group(Identifier=group_id, Description="x"),
        "UpdateCloudWatchAlarmTemplateGroup after delete",
    )
    assert (
        group_update_code == "NotFoundException"
    ), f"expected NotFoundException updating deleted group, got {group_update_code}"
    assert group_update_message is None, f"expected no message updating deleted group, got {group_update_message!r}"


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
