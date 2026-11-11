"""start-command-execution-unknown-and-deprecated-command-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-command-execution-unknown-and-deprecated-command-rejected"
GROUP = 'command-execution-rejected'
SERVICES = ['iot-jobs-data']

# iot-jobs-data is reachable only at the account-specific ATS host
# (data.jobs.iot.<region>.amazonaws.com answers 403 AccessDeniedException for every operation).
_COMMAND_TIMEOUT_S = 120.0
_COMMAND_INTERVAL_S = 2.0
_PAYLOAD = b'{"reboot": true}'


def _jobs_data(ctx):
    """(iot control-plane client, iot-jobs-data client bound to this account's ATS host)."""
    iot = ctx.client("iot")
    host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return iot, ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(host))


def _rejection(fn):
    """(error code, HTTP status, message) of the ClientError fn() raises; raises if fn SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message"),
        )
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


def _poll(fn, predicate, what, timeout_s=_COMMAND_TIMEOUT_S, interval_s=_COMMAND_INTERVAL_S):
    """Poll fn() until predicate holds; command creation and deprecation both propagate."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = fn()
            if predicate(last):
                return last
        except ClientError as exc:
            last = exc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observed {last!r}"
            )
        time.sleep(interval_s)


def _executions_of(iot, command_arn):
    """Every command execution of command_arn, across all pages.

    ListCommandExecutions requires a time filter at minute precision (YYYY-MM-DDThh:mm) and exactly
    one of targetArn or commandArn.
    """
    after = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M")
    out = []
    token = None
    while True:
        page = iot.list_command_executions(
            commandArn=command_arn, startedTimeFilter={"after": after},
            **({"nextToken": token} if token else {}),
        )
        out.extend(page.get("commandExecutions", []))
        token = page.get("nextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCommandExecution rejects unknown, deprecated, bad-target and bad-parameter calls with
    ValidationException/400 (not ResourceNotFoundException), creating no execution; undeprecating
    the command makes the same call succeed again.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-cmdt-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    command_id = ctx.unique_name("sim2real-behav-jd-cmd-")
    created = iot.create_command(
        commandId=command_id, namespace="AWS-IoT", displayName="sim2real reboot",
        payload={"content": _PAYLOAD, "contentType": "application/json"},
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    # Deleting the command also removes its executions, so this is the only teardown needed.
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))
    command_arn = created["commandArn"]

    # Positive control in the same file: the live command starts an execution.
    started = jd.start_command_execution(targetArn=thing_arn, commandArn=command_arn)
    execution_id = started["executionId"]
    assert execution_id, f"StartCommandExecution must return an executionId, got {started!r}"
    control = _poll(
        lambda: iot.get_command_execution(executionId=execution_id, targetArn=thing_arn),
        lambda r: r.get("status") == "CREATED",
        f"command execution {execution_id} reaching CREATED",
    )
    assert control["commandArn"] == command_arn, (
        f"the execution must point at {command_arn!r}, got {control.get('commandArn')!r}"
    )
    assert control["targetArn"] == thing_arn, (
        f"the execution must point at {thing_arn!r}, got {control.get('targetArn')!r}"
    )

    unknown_id = command_id[:-4] + "zzzz"
    unknown_arn = command_arn.replace(command_id, unknown_id)
    unknown_code, unknown_status, unknown_msg = _rejection(
        lambda: jd.start_command_execution(targetArn=thing_arn, commandArn=unknown_arn)
    )
    assert unknown_code == "ValidationException", (
        f"an unknown commandArn must be rejected ValidationException, not the declared "
        f"ResourceNotFoundException; got {unknown_code!r}"
    )
    assert unknown_status == 400, f"expected HTTP 400, got {unknown_status!r}"
    assert unknown_msg == f"The command {unknown_id} was not found.", (
        f"unexpected unknown-command message {unknown_msg!r}"
    )

    malformed_code, malformed_status, malformed_msg = _rejection(
        lambda: jd.start_command_execution(targetArn="not-an-arn", commandArn=command_arn)
    )
    assert malformed_code == "ValidationException", (
        f"a malformed targetArn must be rejected ValidationException, got {malformed_code!r}"
    )
    assert malformed_status == 400, f"expected HTTP 400, got {malformed_status!r}"
    assert malformed_msg == "Invalid target arn not-an-arn not supported as a target", (
        f"unexpected malformed-target message {malformed_msg!r}"
    )

    params_code, params_status, params_msg = _rejection(
        lambda: jd.start_command_execution(
            targetArn=thing_arn, commandArn=command_arn, parameters={"level": {"S": "high"}}
        )
    )
    assert params_code == "ValidationException", (
        f"parameters against a static-payload command must be rejected ValidationException, got "
        f"{params_code!r}"
    )
    assert params_status == 400, f"expected HTTP 400, got {params_status!r}"
    assert params_msg == "The parameters option is unsupported for commands with static payloads.", (
        f"unexpected static-payload message {params_msg!r}"
    )

    iot.update_command(commandId=command_id, deprecated=True)
    deprecated_code, deprecated_status, deprecated_msg = _poll(
        lambda: _rejection(
            lambda: jd.start_command_execution(targetArn=thing_arn, commandArn=command_arn)
        ),
        lambda t: t[2] == f"The command {command_id} has been deprecated.",
        f"{command_id} to be refused as deprecated",
    )
    assert deprecated_code == "ValidationException", (
        f"a deprecated command must be rejected ValidationException, got {deprecated_code!r}"
    )
    assert deprecated_status == 400, f"expected HTTP 400, got {deprecated_status!r}"
    assert deprecated_msg == f"The command {command_id} has been deprecated.", (
        f"unexpected deprecated-command message {deprecated_msg!r}"
    )

    # UpdateCommand's `deprecated` flag is a reversible boolean, so the call succeeds again.
    iot.update_command(commandId=command_id, deprecated=False)
    restored = _poll(
        lambda: jd.start_command_execution(targetArn=thing_arn, commandArn=command_arn),
        lambda r: bool(r.get("executionId")),
        f"{command_id} to be restored and accept a new execution",
    )
    restored_execution_id = restored["executionId"]
    assert restored_execution_id and restored_execution_id != execution_id, (
        f"the restored command must mint a fresh executionId, got {restored_execution_id!r}"
    )
    restored_record = _poll(
        lambda: iot.get_command_execution(executionId=restored_execution_id, targetArn=thing_arn),
        lambda r: r.get("status") == "CREATED",
        f"restored command execution {restored_execution_id} reaching CREATED",
    )
    assert restored_record["commandArn"] == command_arn, (
        f"the restored execution must point at {command_arn!r}, got "
        f"{restored_record.get('commandArn')!r}"
    )

    # Effect absent: the four refusals created no execution — only the control and the restored
    # execution exist.
    executions = _executions_of(iot, command_arn)
    assert {e["executionId"] for e in executions} == {execution_id, restored_execution_id}, (
        f"only the control and restored executions may exist for {command_arn}, got "
        f"{sorted(e['executionId'] for e in executions)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
