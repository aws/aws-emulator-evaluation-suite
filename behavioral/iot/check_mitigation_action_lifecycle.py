"""mitigation-action-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mitigation-action-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created mitigation action describes back as created; after DeleteMitigationAction, both
    describe and UpdateMitigationAction on the name fail with ResourceNotFoundException."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_arn = _create_iot_role(ctx, iam)

    name = ctx.unique_name("sim2real-mitigation-")
    action_params = {"updateDeviceCertificateParams": {"action": "DEACTIVATE"}}
    created = _retry_while(
        lambda: iot.create_mitigation_action(actionName=name, roleArn=role_arn, actionParams=action_params),
        retry_codes={"InvalidRequestException"},
        timeout_s=20.0,
    )
    ctx.on_cleanup(lambda: _delete_action_quiet(iot, name))
    assert created["actionArn"], f"CreateMitigationAction returned no actionArn: {created!r}"

    described = iot.describe_mitigation_action(actionName=name)
    assert described["actionName"] == name, (
        f"expected actionName {name!r}, got {described['actionName']!r}"
    )
    assert described["roleArn"] == role_arn, (
        f"expected roleArn {role_arn!r}, got {described['roleArn']!r}"
    )
    assert described["actionParams"] == action_params, (
        f"expected actionParams {action_params!r}, got {described['actionParams']!r}"
    )
    assert described["actionType"] == "UPDATE_DEVICE_CERTIFICATE", (
        f"expected actionType 'UPDATE_DEVICE_CERTIFICATE', got {described['actionType']!r}"
    )

    iot.delete_mitigation_action(actionName=name)

    error, message = _error(lambda: iot.describe_mitigation_action(actionName=name))
    assert error == "ResourceNotFoundException", (
        f"expected DescribeMitigationAction on the deleted action {name!r} to fail with "
        f"'ResourceNotFoundException', got {error!r}"
    )
    assert message == f"No action with name {name} is found", message

    update_error, update_message = _error(
        lambda: iot.update_mitigation_action(actionName=name, roleArn=role_arn, actionParams=action_params)
    )
    assert update_error == "ResourceNotFoundException", (
        f"expected UpdateMitigationAction on the deleted action {name!r} to fail with "
        f"'ResourceNotFoundException', got {update_error!r}"
    )
    assert update_message == f"Resource findingActionName={name} was not found", update_message


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _retry_while(fn, retry_codes, timeout_s=20.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_iot_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-iot-mitigation-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))
    return role["Arn"]


def _delete_role_quiet(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_action_quiet(iot, name):
    iot.delete_mitigation_action(actionName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
