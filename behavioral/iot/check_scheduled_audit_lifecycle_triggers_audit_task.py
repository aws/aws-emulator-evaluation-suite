"""scheduled-audit-lifecycle-triggers-audit-task."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduled-audit-lifecycle-triggers-audit-task"
GROUP = "state-machine"
SERVICES = ["iot"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-audit-configuration")
def run(ctx) -> None:
    """A scheduled audit is described and listed after create and is gone right after delete;
    a repeat DeleteScheduledAudit is rejected with ResourceNotFoundException, not a silent success.
    """
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    # Scheduled audits require the referenced check to be enabled for the account.
    role_name = ctx.unique_name("sim2real-auditrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    check_name = "DEVICE_CERTIFICATE_EXPIRING_CHECK"
    # the audit configuration is account-wide: read it now and put it back after the check
    prior = iot.describe_account_audit_configuration()
    iot.update_account_audit_configuration(
        roleArn=role_arn, auditCheckConfigurations={check_name: {"enabled": True}}
    )
    ctx.on_cleanup(lambda: _restore_audit_configuration(iot, prior))

    # A scheduled audit runs only at its UTC day/week boundary, so no audit task run is awaited.
    name = ctx.unique_name("sim2real-schedaudit-")
    created = iot.create_scheduled_audit(
        frequency="DAILY",
        targetCheckNames=[check_name],
        scheduledAuditName=name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(iot, name))
    assert created["scheduledAuditArn"], f"expected a non-empty ARN, got {created['scheduledAuditArn']!r}"

    described = iot.describe_scheduled_audit(scheduledAuditName=name)
    assert described["frequency"] == "DAILY", f"expected frequency DAILY, got {described['frequency']!r}"
    assert described["targetCheckNames"] == [check_name], (
        f"expected targetCheckNames [{check_name!r}], got {described['targetCheckNames']!r}"
    )

    names = [a["scheduledAuditName"] for a in iot.list_scheduled_audits()["scheduledAudits"]]
    assert name in names, f"expected {name!r} in ListScheduledAudits, got {names!r}"

    iot.delete_scheduled_audit(scheduledAuditName=name)
    code_gone, code_gone_message = _error(lambda: iot.describe_scheduled_audit(scheduledAuditName=name))
    assert code_gone == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeScheduledAudit after delete, got {code_gone!r}"
    )
    assert code_gone_message == f"Resource scheduledAuditName={name} was not found", (
        f"expected the exact {code_gone} message, got {code_gone_message!r}"
    )

    # DeleteScheduledAudit (unlike DeleteMitigationAction) DOES model
    # ResourceNotFoundException -- a repeat delete must fail, not silently succeed.
    code_repeat, code_repeat_message = _error(lambda: iot.delete_scheduled_audit(scheduledAuditName=name))
    assert code_repeat == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from a repeat DeleteScheduledAudit, got {code_repeat!r}"
    )
    assert code_repeat_message == f"Resource scheduledAuditName={name} was not found", (
        f"expected the exact {code_repeat} message, got {code_repeat_message!r}"
    )


def _safe_delete(iot, name: str) -> None:
    try:
        iot.delete_scheduled_audit(scheduledAuditName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _restore_audit_configuration(iot, prior):
    """Put back the account audit configuration read before the check: delete it when it had no
    role, otherwise restore its role, its notification targets and every check's setting."""
    if not prior.get("roleArn"):
        iot.delete_account_audit_configuration(deleteScheduledAudits=False)
        return
    kwargs = {"roleArn": prior["roleArn"], "auditCheckConfigurations": prior.get("auditCheckConfigurations", {})}
    if prior.get("auditNotificationTargetConfigurations"):
        kwargs["auditNotificationTargetConfigurations"] = prior["auditNotificationTargetConfigurations"]
    iot.update_account_audit_configuration(**kwargs)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
