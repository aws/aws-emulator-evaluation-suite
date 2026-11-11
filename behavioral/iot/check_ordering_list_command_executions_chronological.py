"""ordering-list-command-executions-chronological."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ordering-list-command-executions-chronological"
GROUP = "ordering"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListCommandExecutions for a command returns its executions in start order
    ascending, in reverse descending, and in the same order across pages."""
    iot = ctx.client("iot")
    # iot:Data-ATS is the recommended endpoint type for Jobs/Commands (the
    # legacy iot:Jobs IPv4-only type is being retired in favor of it).
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    jobs_data = ctx.client("iot-jobs-data", endpoint_url=ctx.endpoint_url(endpoint))

    command_id = ctx.unique_name("sim2real-cmd-")
    created = iot.create_command(
        commandId=command_id,
        namespace="AWS-IoT",
        payload={"content": b'{"action":"noop"}', "contentType": "application/json"},
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    command_arn = created["commandArn"]
    ctx.on_cleanup(lambda: _safe_delete_command(iot, command_id))

    thing_names = [ctx.unique_name(f"sim2real-cmdthing-{i}-") for i in range(3)]
    thing_arns = []
    for n in thing_names:
        arn = iot.create_thing(thingName=n)["thingArn"]
        thing_arns.append(arn)
        ctx.on_cleanup(lambda n=n: iot.delete_thing(thingName=n))

    execution_ids = []
    for arn in thing_arns:
        resp = jobs_data.start_command_execution(commandArn=command_arn, targetArn=arn)
        execution_ids.append(resp["executionId"])
        ctx.on_cleanup(lambda arn=arn, eid=resp["executionId"]: _safe_delete_execution(iot, eid, arn))
        time.sleep(1.5)  # ensure distinguishable createdAt timestamps

    # ListCommandExecutions requires exactly one of startedTimeFilter or
    # completedTimeFilter; use a wide-open startedTimeFilter to include every
    # execution created in this run.
    time_filter = {"after": "2020-01-01T00:00"}

    ascending = _list_all(iot, command_arn, "ASCENDING", time_filter)
    ascending_ids = [e["executionId"] for e in ascending]
    assert ascending_ids == execution_ids, (
        f"ASCENDING order expected {execution_ids} (creation order), got {ascending_ids}"
    )

    descending = _list_all(iot, command_arn, "DESCENDING", time_filter)
    descending_ids = [e["executionId"] for e in descending]
    expected_descending = list(reversed(execution_ids))
    assert descending_ids == expected_descending, (
        f"DESCENDING order expected {expected_descending} (reverse creation order), "
        f"got {descending_ids}"
    )

    # Pagination must not reorder or drop/duplicate entries relative to the
    # single-page ascending listing.
    paged_ids = []
    next_token = None
    while True:
        kwargs = {
            "commandArn": command_arn,
            "sortOrder": "ASCENDING",
            "maxResults": 1,
            "startedTimeFilter": time_filter,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        page = iot.list_command_executions(**kwargs)
        paged_ids.extend(e["executionId"] for e in page["commandExecutions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert paged_ids == execution_ids, (
        f"paginated ASCENDING listing (maxResults=1) expected {execution_ids}, got {paged_ids}"
    )


def _list_all(iot, command_arn: str, sort_order: str, time_filter: dict):
    out = []
    next_token = None
    while True:
        kwargs = {
            "commandArn": command_arn,
            "sortOrder": sort_order,
            "startedTimeFilter": time_filter,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        page = iot.list_command_executions(**kwargs)
        out.extend(page["commandExecutions"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return out


def _safe_delete_execution(iot, execution_id: str, target_arn: str) -> None:
    iot.delete_command_execution(executionId=execution_id, targetArn=target_arn)


def _safe_delete_command(iot, command_id: str) -> None:
    iot.delete_command(commandId=command_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
