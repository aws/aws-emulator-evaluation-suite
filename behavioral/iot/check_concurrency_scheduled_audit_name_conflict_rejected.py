"""concurrency-scheduled-audit-name-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrency-scheduled-audit-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-audit-configuration")
def run(ctx) -> None:
    """Creating a scheduled audit under a name already in use fails with
    ResourceAlreadyExistsException and leaves the existing DAILY schedule unchanged;
    a differently-named scheduled audit still succeeds."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-audit-role")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    check_name = "DEVICE_CERTIFICATE_EXPIRING_CHECK"

    def _enable_check():
        iot.update_account_audit_configuration(
            roleArn=role_arn,
            auditCheckConfigurations={check_name: {"enabled": True}},
        )

    # the audit configuration is account-wide: read it now and put it back after the check
    prior = iot.describe_account_audit_configuration()
    _retry(_enable_check, exceptions=(ClientError,), attempts=6, delay_s=3.0)
    ctx.on_cleanup(lambda: _restore_audit_configuration(iot, prior))

    audit_name = ctx.unique_name("sim2real-schedaudit")
    iot.create_scheduled_audit(
        scheduledAuditName=audit_name,
        frequency="DAILY",
        targetCheckNames=[check_name],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_scheduled_audit(scheduledAuditName=audit_name))

    err = _error(
        lambda: iot.create_scheduled_audit(
            scheduledAuditName=audit_name,
            frequency="WEEKLY",
            dayOfWeek="MON",
            targetCheckNames=[check_name],
        )
    )
    assert err == ("ResourceAlreadyExistsException", (
        "Resource already exists for account with different attributes, "
        f"arn:aws:iot:{ctx.region}:{ctx.account}:scheduledaudit/{audit_name}"
    )), err

    described = iot.describe_scheduled_audit(scheduledAuditName=audit_name)
    assert described["frequency"] == "DAILY", f"expected frequency=DAILY (unchanged), got {described}"
    assert "dayOfWeek" not in described or not described["dayOfWeek"], (
        f"expected no dayOfWeek (WEEKLY update must not have applied), got {described}"
    )

    other_audit_name = ctx.unique_name("sim2real-schedaudit-2")
    iot.create_scheduled_audit(
        scheduledAuditName=other_audit_name,
        frequency="WEEKLY",
        dayOfWeek="MON",
        targetCheckNames=[check_name],
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_scheduled_audit(scheduledAuditName=other_audit_name))
    described_other = iot.describe_scheduled_audit(scheduledAuditName=other_audit_name)
    assert described_other["frequency"] == "WEEKLY", (
        f"expected frequency=WEEKLY for differently-named audit, got {described_other}"
    )


def _error(fn):
    """The AWS (code, message) *fn* raised. Raises if it succeeded, so success is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry(fn, *, exceptions, attempts: int, delay_s: float):
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except exceptions as e:  # noqa: PERF203 - small bounded retry loop
            last_exc = e
            if i == attempts - 1:
                raise
            time.sleep(delay_s)
    raise last_exc  # pragma: no cover


def _restore_audit_configuration(iot, prior):
    """Restore the prior account audit configuration, or delete it when it had no role."""
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
