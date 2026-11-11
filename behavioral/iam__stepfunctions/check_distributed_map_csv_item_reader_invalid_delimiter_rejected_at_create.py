"""distributed-map-csv-item-reader-invalid-delimiter-rejected-at-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distributed-map-csv-item-reader-invalid-delimiter-rejected-at-create"
GROUP = "distributed_map"
SERVICES = ["iam", "stepfunctions"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})


def _valid_definition() -> dict:
    return {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}


def _map_definition(*, csv_delimiter) -> dict:
    return {
        "StartAt": "Items",
        "States": {
            "Items": {
                "Type": "Map",
                "ItemReader": {
                    "Resource": "arn:aws:states:::s3:getObject",
                    "ReaderConfig": {
                        "InputType": "CSV", "CSVHeaderLocation": "FIRST_ROW",
                        "CSVDelimiter": csv_delimiter,
                    },
                    "Parameters": {"Bucket": "sim2real-unused-bucket", "Key": "rows.csv"},
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Identity",
                    "States": {"Identity": {"Type": "Pass", "End": True}},
                },
                "End": True,
            },
        },
    }


def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-dmapcsvdelimrole-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
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


def _refusal(fn):
    """Call fn(); return the (code, message) it is refused with. A success raises, so a target
    that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


_EXPECTED_REFUSAL = (
    "InvalidDefinition",
    "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: Value should be one of the "
    "following: [COMMA, SEMICOLON, PIPE, SPACE, TAB] at "
    "/States/Items/ItemReader/ReaderConfig/CSVDelimiter'",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine rejects a Distributed Map CSV ItemReader whose CSVDelimiter is
    outside COMMA|PIPE|SEMICOLON|SPACE|TAB; a well-formed definition on the same role still
    succeeds, and the rejected attempt never shows up in the account's state machine list.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-itemreader.html
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)

    valid_name = ctx.unique_name("sim2real-behav-sm-valid-")
    valid_arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=valid_name, definition=json.dumps(_valid_definition()), roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=valid_arn))
    desc = sfn.describe_state_machine(stateMachineArn=valid_arn)
    assert desc["status"] == "ACTIVE", f"expected ACTIVE, got {desc['status']!r}"

    invalid_name = ctx.unique_name("sim2real-behav-sm-invalid-")
    code, message = _refusal(
        lambda: sfn.create_state_machine(
            name=invalid_name, definition=json.dumps(_map_definition(csv_delimiter="COLON")),
            roleArn=role_arn,
        )
    )
    assert (code, message) == _EXPECTED_REFUSAL, (
        f"expected {_EXPECTED_REFUSAL!r}, got {(code, message)!r}"
    )

    names = [
        sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])
    ]
    assert invalid_name not in names, (
        f"{invalid_name} should not exist after an InvalidDefinition rejection"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
