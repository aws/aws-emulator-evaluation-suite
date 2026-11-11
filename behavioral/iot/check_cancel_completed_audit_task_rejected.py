"""cancel-completed-audit-task-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-completed-audit-task-rejected"
GROUP = "error-semantics"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-audit-configuration")
def run(ctx) -> None:
    """CancelAuditTask on a COMPLETED audit task is rejected with InvalidRequestException and the
    status stays COMPLETED; cancelling a freshly started task is accepted (or refused naming the
    terminal state it already reached)."""
    iot = ctx.client("iot")
    role_arn = _create_audit_role(ctx)

    # LOGGING_DISABLED_CHECK inspects only the logging configuration, so it completes fastest.
    fast_check = ["LOGGING_DISABLED_CHECK"]
    _enable_checks(ctx, iot, role_arn, fast_check)

    task_id = _run_audit_task_to_completion(iot, fast_check)

    code, message = _error_code(lambda: iot.cancel_audit_task(taskId=task_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == f"Task {task_id} is now in COMPLETED status and cannot be canceled", (
        f"expected the exact InvalidRequestException message naming the COMPLETED task, got {message!r}"
    )

    unaffected = iot.describe_audit_task(taskId=task_id)["taskStatus"]
    assert unaffected == "COMPLETED", f"expected status to stay COMPLETED, got {unaffected!r}"

    # positive control: a freshly started task can be cancelled while still in progress
    control_task_id = iot.start_on_demand_audit_task(targetCheckNames=fast_check)["taskId"]
    try:
        iot.cancel_audit_task(taskId=control_task_id)
    except ClientError as exc:
        # the task already reached a terminal state before we could cancel it
        reached = iot.describe_audit_task(taskId=control_task_id)["taskStatus"]
        refusal = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
        assert refusal == (
            "InvalidRequestException",
            f"Task {control_task_id} is now in {reached} status and cannot be canceled",
        ), f"expected InvalidRequestException for a control task already {reached}, got {refusal!r}"
    else:
        control_status = _poll_until(
            lambda: iot.describe_audit_task(taskId=control_task_id)["taskStatus"],
            lambda s: s in ("CANCELED", "COMPLETED", "FAILED"),
            timeout_s=max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0)),
            interval_s=3,
        )
        assert control_status == "CANCELED", (
            f"expected the successfully cancelled control task to land on CANCELED, "
            f"got {control_status!r}"
        )


# ===== helpers =====

def _create_audit_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-audit-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTDeviceDefenderAudit"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _enable_checks(ctx, iot, role_arn, check_names):
    previous = iot.describe_account_audit_configuration()
    had_prior_config = bool(previous.get("roleArn"))

    def _restore():
        try:
            if had_prior_config:
                iot.update_account_audit_configuration(
                    roleArn=previous["roleArn"],
                    auditNotificationTargetConfigurations=previous.get(
                        "auditNotificationTargetConfigurations", {}
                    ),
                    auditCheckConfigurations=previous.get("auditCheckConfigurations", {}),
                )
            else:
                iot.delete_account_audit_configuration()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_restore)

    check_config = {name: {"enabled": True} for name in check_names}
    _retry_on_codes(
        lambda: iot.update_account_audit_configuration(
            roleArn=role_arn, auditCheckConfigurations=check_config
        ),
        codes=("InvalidRequestException",),
        timeout_s=45,
    )


def _run_audit_task_to_completion(iot, check_names, retry_deadline_s=90.0, backoff_s=10.0):
    """Run an on-demand audit task to COMPLETED, starting a fresh task while a just-attached role
    is still rejected as INSUFFICIENT_PERMISSIONS (IAM propagation; a FAILED task cannot resume).
    Bounded by retry_deadline_s so a real permissions defect still fails."""
    deadline = time.monotonic() + retry_deadline_s
    while True:
        task_id = iot.start_on_demand_audit_task(targetCheckNames=check_names)["taskId"]
        final_status = _poll_until(
            lambda: iot.describe_audit_task(taskId=task_id)["taskStatus"],
            lambda s: s in ("COMPLETED", "FAILED", "CANCELED"),
            timeout_s=180,
            interval_s=5,
        )
        if final_status == "COMPLETED":
            return task_id
        detail = iot.describe_audit_task(taskId=task_id)
        codes = {c.get("errorCode") for c in detail.get("auditDetails", {}).values()}
        if codes == {"INSUFFICIENT_PERMISSIONS"} and time.monotonic() < deadline:
            time.sleep(backoff_s)
            continue
        raise AssertionError(
            f"audit task {task_id} did not complete: status={final_status}, detail={detail!r}"
        )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last}")


def _retry_on_codes(fn, codes, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error_code(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
