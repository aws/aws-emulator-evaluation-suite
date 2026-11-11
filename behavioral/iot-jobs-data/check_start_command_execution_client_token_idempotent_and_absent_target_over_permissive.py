"""start-command-execution-client-token-idempotent-and-absent-target-over-permissive."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-command-execution-client-token-idempotent-and-absent-target-over-permissive"
GROUP = 'command-execution-over-permissive'
SERVICES = ['iot-jobs-data']

# iot-jobs-data is reachable only at the account-specific ATS host
# (data.jobs.iot.<region>.amazonaws.com answers 403 AccessDeniedException for every operation).
_COMMAND_TIMEOUT_S = 120.0
_COMMAND_INTERVAL_S = 2.0
_PAYLOAD = b'{"reboot": true}'
_GHOST_EXECUTION_TIMEOUT_S = 10
_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED", "REJECTED", "TIMED_OUT"}


def _jobs_data(ctx):
    """(iot control-plane client, iot-jobs-data client bound to this account's ATS host)."""
    iot = ctx.client("iot")
    host = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return iot, ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(host))


def _poll(fn, predicate, what, timeout_s=_COMMAND_TIMEOUT_S, interval_s=_COMMAND_INTERVAL_S):
    """Poll fn() until predicate holds; the command execution record is created asynchronously."""
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


def _all_thing_names(iot):
    """Every registry thing name, across all ListThings pages."""
    names = []
    token = None
    while True:
        page = iot.list_things(**({"nextToken": token} if token else {}))
        names.extend(t["thingName"] for t in page.get("things", []))
        token = page.get("nextToken")
        if not token:
            return names


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCommandExecution with a repeated clientToken returns the same executionId and creates one
    execution, and a target thing absent from the registry is accepted and ends TIMED_OUT.
    """
    iot, jd = _jobs_data(ctx)

    thing = ctx.unique_name("sim2real-behav-jd-idem-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing))
    thing_arn = iot.describe_thing(thingName=thing)["thingArn"]

    command_id = ctx.unique_name("sim2real-behav-jd-idemcmd-")
    created = iot.create_command(
        commandId=command_id, namespace="AWS-IoT", displayName="sim2real reboot",
        payload={"content": _PAYLOAD, "contentType": "application/json"},
        tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    # Deleting the command also removes its executions, including the one minted against the
    # absent target below, which has no other handle.
    ctx.on_cleanup(lambda: iot.delete_command(commandId=command_id))
    command_arn = created["commandArn"]

    token = ctx.unique_name("sim2real-behav-jd-tok-")
    first = jd.start_command_execution(
        targetArn=thing_arn, commandArn=command_arn, clientToken=token
    )["executionId"]
    second = jd.start_command_execution(
        targetArn=thing_arn, commandArn=command_arn, clientToken=token
    )["executionId"]
    assert second == first, (
        f"the same clientToken must return the same executionId: first {first!r}, second "
        f"{second!r}"
    )
    _poll(
        lambda: _executions_of(iot, command_arn),
        lambda es: [e["executionId"] for e in es] == [first],
        f"exactly one command execution for {command_arn}",
    )

    fresh = jd.start_command_execution(targetArn=thing_arn, commandArn=command_arn)["executionId"]
    assert fresh != first, (
        f"a request with NO clientToken must mint a new execution, got {fresh!r} again"
    )
    both = _poll(
        lambda: _executions_of(iot, command_arn),
        lambda es: len(es) == 2,
        f"two command executions for {command_arn}",
    )
    assert {e["executionId"] for e in both} == {first, fresh}, (
        f"the two executions must be exactly {first!r} and {fresh!r}, got "
        f"{sorted(e['executionId'] for e in both)!r}"
    )

    ghost = ctx.unique_name("sim2real-behav-jd-ghost-")
    registry = _all_thing_names(iot)
    assert ghost not in registry, (
        f"precondition: {ghost!r} must not be in the registry, but ListThings returned it"
    )
    ghost_arn = thing_arn.replace(thing, ghost)
    ghost_execution = jd.start_command_execution(
        targetArn=ghost_arn, commandArn=command_arn,
        executionTimeoutSeconds=_GHOST_EXECUTION_TIMEOUT_S,
    )["executionId"]
    assert ghost_execution, (
        f"a target thing that does not exist must still be ACCEPTED, got {ghost_execution!r}"
    )
    assert ghost_execution not in {first, fresh}, (
        f"the absent-target execution must be its own record, got {ghost_execution!r}"
    )
    # No device reads an absent thing's topic, so the execution's resting state is the timer's
    # terminal TIMED_OUT; CREATED is only the window before that.
    ghost_record = _poll(
        lambda: iot.get_command_execution(executionId=ghost_execution, targetArn=ghost_arn),
        lambda r: r.get("status") in _TERMINAL_STATUSES,
        f"the execution against the absent thing {ghost} reaching a terminal status",
    )
    assert ghost_record["status"] == "TIMED_OUT", (
        f"an execution no device can pick up must end TIMED_OUT, got {ghost_record['status']!r}"
    )
    assert ghost_record["targetArn"] == ghost_arn, (
        f"the execution must record the absent target verbatim, got "
        f"{ghost_record.get('targetArn')!r}"
    )
    assert ghost not in _all_thing_names(iot), (
        f"accepting the execution must NOT have created the thing {ghost!r} in the registry"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
