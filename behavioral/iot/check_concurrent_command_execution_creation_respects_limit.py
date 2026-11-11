"""concurrent-command-execution-creation-respects-limit."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-command-execution-creation-respects-limit"
GROUP = "concurrency"
SERVICES = ["iot"]

# AWS IoT publishes a "Command execution concurrency limit" of 100 concurrent (non-terminal)
# command executions per target device (non-adjustable, per AWS IoT Device Management quotas).
# A fast concurrent burst against that boundary is enforced via admission-control
# throttling (ThrottlingException) rather than always surfacing the documented
# ServiceQuotaExceededException -- either is a legitimate "this request was not admitted"
# signal, so the check accepts both rather than assuming one specific wire code.
_DEVICE_CONCURRENCY_LIMIT = 100
_ATTEMPTS = _DEVICE_CONCURRENCY_LIMIT + 50
_REJECTION_CODES = {"ServiceQuotaExceededException", "ThrottlingException"}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A burst of StartCommandExecution calls on one thing is partly refused with
    ServiceQuotaExceededException or ThrottlingException, and each admitted execution is
    listed and retrievable for that thing."""
    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-cmdtarget-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: _delete_thing(iot, thing_name))

    # The IoT jobs-data plane requires the account-specific ATS data endpoint (not
    # botocore's generic regional default) -- calling without it fails with
    # AccessDeniedException "Invalid endpoint. Use describe-endpoint API to get valid endpoint."
    endpoint_addr = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(endpoint_addr))

    command_id = ctx.unique_name("sim2real-cmd-")
    command_arn = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b"ping", "contentType": "text/plain"},
        tags=[{"Key": "sim2real", "Value": "concurrent-command-execution-creation-respects-limit"}],
    )["commandArn"]
    ctx.on_cleanup(lambda: _delete_command(iot, command_id))
    _wait_for_command_ready(iot, command_id)

    # Warm-up: IAM's resource-based authorization for a brand-new thing/command pair can lag
    # a few seconds behind the control-plane CreateThing/CreateCommand response (the calls
    # above return success before the resources are visible to the jobs-data authorizer).
    # Poll a single StartCommandExecution call to a real, distinct success before firing the
    # concurrency burst, so the burst measures admission control -- not create-to-authorize lag.
    warmup_execution_id = _wait_for_start_command_ready(jobs_data, command_arn, thing_arn)

    burst_started_at = _utc_now_minus(60)

    def _start(_: int):

        try:
            resp = jobs_data.start_command_execution(
                commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=3600
            )
            return ("ok", resp["executionId"])
        except ClientError as e:
            return ("err", e.response["Error"]["Code"])
        except Exception as e:  # pragma: no cover -- connection-level errors under high concurrency
            return ("err", f"{type(e).__name__}:{e}")

    with ThreadPoolExecutor(max_workers=50) as pool:
        results = list(pool.map(_start, range(_ATTEMPTS)))

    successes = [warmup_execution_id] + [r[1] for r in results if r[0] == "ok"]
    failures = [r[1] for r in results if r[0] == "err"]

    ctx.on_cleanup(lambda: _delete_executions(iot, thing_arn, successes))

    assert len(successes) + len(failures) == _ATTEMPTS + 1, (
        f"expected {_ATTEMPTS} burst results plus the warm-up success, got "
        f"{len(successes)} successes + {len(failures)} failures"
    )
    assert len(failures) > 0, (
        "expected at least one execution rejected by admission control under a "
        f"{_ATTEMPTS}-call burst against the {_DEVICE_CONCURRENCY_LIMIT}-execution device quota "
        "-- every request was silently admitted"
    )
    assert len(successes) < _ATTEMPTS + 1, "every request was admitted; burst was not throttled at all"
    unexpected_codes = set(failures) - _REJECTION_CODES
    assert not unexpected_codes, f"unexpected rejection codes: {unexpected_codes}"

    # effect check: the device's own admitted-execution count matches exactly what we
    # observed as successes -- no phantom extra admissions beyond what the API returned.
    listed = _list_all_command_executions(iot, thing_arn, burst_started_at)
    assert len(listed) == len(successes), (
        f"expected list_command_executions to report exactly the {len(successes)} admitted "
        f"executions, got {len(listed)} -- phantom or missing admissions"
    )

    # positive control: an admitted execution is a real, retrievable execution record.
    sample_id = successes[0]
    execution = iot.get_command_execution(executionId=sample_id, targetArn=thing_arn)
    assert execution["status"] in ("CREATED", "IN_PROGRESS"), (
        f"expected admitted execution {sample_id!r} to be CREATED or IN_PROGRESS, "
        f"got {execution['status']!r}"
    )
    assert execution["targetArn"] == thing_arn, (
        f"expected execution {sample_id!r} targetArn to be {thing_arn!r}, "
        f"got {execution['targetArn']!r}"
    )


def _utc_now_minus(seconds: float) -> str:
    import datetime

    return (
        (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds))
        .strftime("%Y-%m-%dT%H:%M")
    )


def _list_all_command_executions(iot, thing_arn: str, started_after: str) -> list:
    executions: list = []
    next_token = None
    while True:
        kwargs = {
            "targetArn": thing_arn,
            "startedTimeFilter": {"after": started_after},
            "maxResults": 100,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        resp = iot.list_command_executions(**kwargs)
        executions.extend(resp.get("commandExecutions", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return executions


def _wait_for_command_ready(iot, command_id: str, timeout_s: float = 20.0) -> None:

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            iot.get_command(commandId=command_id)
            return
        except ClientError as e:
            last_exc = e
            time.sleep(1.0)
    raise AssertionError(f"command {command_id!r} never became readable after creation: {last_exc}")


def _wait_for_start_command_ready(jobs_data, command_arn: str, thing_arn: str, timeout_s: float = 30.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = jobs_data.start_command_execution(
                commandArn=command_arn, targetArn=thing_arn, executionTimeoutSeconds=3600
            )
            return resp["executionId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "AccessDeniedException":
                raise
            last_exc = e
            time.sleep(2.0)
    raise AssertionError(
        f"StartCommandExecution never became authorized for a freshly created thing/command "
        f"pair after {timeout_s}s: {last_exc}"
    )


def _delete_executions(iot, thing_arn: str, execution_ids) -> None:
    for execution_id in execution_ids:
        iot.delete_command_execution(executionId=execution_id, targetArn=thing_arn)


def _delete_command(iot, command_id: str) -> None:
    iot.delete_command(commandId=command_id)


def _delete_thing(iot, thing_name: str) -> None:
    try:
        iot.delete_thing(thingName=thing_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
