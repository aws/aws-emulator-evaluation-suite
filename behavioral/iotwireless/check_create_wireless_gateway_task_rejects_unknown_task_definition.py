"""create-wireless-gateway-task-rejects-unknown-task-definition."""
from __future__ import annotations

import secrets

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-wireless-gateway-task-rejects-unknown-task-definition"
GROUP = 'wireless-gateway-task'
SERVICES = ['iotwireless']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWirelessGatewayTask against a task definition id that does not exist is a
    ResourceNotFoundException and leaves the gateway's task unset; the same call against a real
    task definition schedules a PENDING task, and DeleteWirelessGatewayTask clears it again.
    """
    c = ctx.client("iotwireless")
    iam = ctx.client("iam")

    gateway_eui = secrets.token_hex(8)
    gateway = c.create_wireless_gateway(
        Name=ctx.unique_name("sim2real-behav-iotw-gw-"), LoRaWAN={"GatewayEui": gateway_eui, "RfRegion": "US915"}
    )
    gateway_id = gateway["Id"]
    ctx.on_cleanup(_teardown(lambda: c.delete_wireless_gateway(Id=gateway_id), "ResourceNotFoundException"))

    role = iam.create_role(
        RoleName=ctx.unique_name("sim2real-behav-iotw-wgtdrole-"),
        AssumeRolePolicyDocument=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"iotwireless.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
        ),
    )
    role_name = role["Role"]["RoleName"]
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    task_definition = c.create_wireless_gateway_task_definition(
        AutoCreateTasks=False,
        Name=ctx.unique_name("sim2real-behav-iotw-wgtd-"),
        Update={
            "UpdateDataSource": "s3://sim2real-behav-bucket/firmware.bin",
            "UpdateDataRole": role_arn,
            "LoRaWAN": {
                "UpdateSignature": "sim2real-behav-signature",
                "SigKeyCrc": 12345,
                "CurrentVersion": {"PackageVersion": "1.0", "Model": "sim2real-behav-model", "Station": "s1"},
                "UpdateVersion": {"PackageVersion": "2.0", "Model": "sim2real-behav-model", "Station": "s1"},
            },
        },
    )
    task_definition_id = task_definition["Id"]
    ctx.on_cleanup(
        _teardown(
            lambda: c.delete_wireless_gateway_task_definition(Id=task_definition_id),
            "ResourceNotFoundException",
        )
    )

    bogus_definition_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(
        lambda: c.create_wireless_gateway_task(Id=gateway_id, WirelessGatewayTaskDefinitionId=bogus_definition_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == (
        "Cannot complete the step because resource is not found, with resource type "
        f"WirelessGatewayTaskDefinition, resource Id {bogus_definition_id}"
    ), f"unexpected message {message!r}"

    before = c.get_wireless_gateway_task(Id=gateway_id)
    assert "Status" not in before, (
        f"the rejected task must leave no task scheduled, got Status {before.get('Status')!r}"
    )

    c.create_wireless_gateway_task(Id=gateway_id, WirelessGatewayTaskDefinitionId=task_definition_id)
    ctx.on_cleanup(_teardown(lambda: c.delete_wireless_gateway_task(Id=gateway_id), "ResourceNotFoundException"))

    scheduled = c.get_wireless_gateway_task(Id=gateway_id)
    assert scheduled["Status"] == "PENDING", f"expected a PENDING task, got {scheduled['Status']!r}"
    assert scheduled["WirelessGatewayTaskDefinitionId"] == task_definition_id, (
        f"expected task definition {task_definition_id!r}, got {scheduled['WirelessGatewayTaskDefinitionId']!r}"
    )

    c.delete_wireless_gateway_task(Id=gateway_id)
    after_delete = c.get_wireless_gateway_task(Id=gateway_id)
    assert "Status" not in after_delete, (
        f"expected the task cleared after delete, got Status {after_delete.get('Status')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
