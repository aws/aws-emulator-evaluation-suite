"""e2e-data-pipeline."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-data-pipeline"
GROUP = 'e2e_workflows'
SERVICES = ['stepfunctions']

def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _run_to_completion(ctx, definition, input_data=None, *, timeout_s=30):
    arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, arn, input_data=input_data)
    return _wait_execution_complete(ctx, exec_arn, timeout_s=timeout_s)


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ETL data pipeline: extract raw data, Map transform each record, load results."""
    definition = {
        "StartAt": "extract",
        "States": {
            "extract": {
                "Type": "Pass",
                "Comment": "Simulate extraction — inject raw records into state",
                "Parameters": {
                    "records.$": "$.records",
                },
                "Next": "transform",
            },
            "transform": {
                "Type": "Map",
                "ItemsPath": "$.records",
                "ResultPath": "$.processed_records",
                "Iterator": {
                    "StartAt": "process_record",
                    "States": {
                        "process_record": {
                            "Type": "Pass",
                            "Parameters": {
                                "id.$": "$.id",
                                "processed": True,
                            },
                            "End": True,
                        }
                    },
                },
                "Next": "load",
            },
            "load": {
                "Type": "Pass",
                "Comment": "Simulate load — pass through processed records as final output",
                "Parameters": {
                    "pipeline_complete": True,
                    "record_count.$": "States.ArrayLength($.processed_records)",
                    "results.$": "$.processed_records",
                },
                "End": True,
            },
        },
    }

    input_data = {"records": [{"id": 1}, {"id": 2}, {"id": 3}]}
    result = _run_to_completion(ctx, definition, input_data)
    assert result["status"] == "SUCCEEDED", f"Pipeline failed: {result.get('error')}"
    output = _get_output(result)

    # Verify output has 3 processed records
    assert output["pipeline_complete"] is True, (
        f"Expected pipeline_complete=True, got {output.get('pipeline_complete')!r}"
    )
    results = output["results"]
    assert isinstance(results, list), f"Expected list of results, got {type(results)}"
    assert len(results) == 3, f"Expected 3 processed records, got {len(results)}"
    assert output["record_count"] == 3, (
        f"States.ArrayLength intrinsic: expected 3, got {output.get('record_count')!r}"
    )

    # Verify each record has "processed": true
    for record in results:
        assert record.get("processed") is True, f"Record missing processed=true: {record}"

    # Verify IDs are preserved
    ids = {record["id"] for record in results}
    assert ids == {1, 2, 3}, f"Expected ids {{1, 2, 3}}, got {ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
