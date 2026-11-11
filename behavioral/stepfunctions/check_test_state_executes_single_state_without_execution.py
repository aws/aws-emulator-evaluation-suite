"""test-state-executes-single-state-without-execution."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "test-state-executes-single-state-without-execution"
GROUP = "server-side"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState runs one state in isolation server-side: it applies real ASL data-flow
    processing (Result/ResultPath merge) and returns output, without creating any
    persisted execution or state machine artifact."""
    sfn = ctx.client("stepfunctions")

    before = _list_all_state_machine_names(ctx)

    definition = json.dumps(
        {
            "Type": "Pass",
            "Result": {"processed": True, "stage": "probe"},
            "ResultPath": "$.enrichment",
            "End": True,
        }
    )
    test_input = json.dumps({"orig": "value", "n": 1})

    resp = sfn.test_state(definition=definition, input=test_input, inspectionLevel="INFO")

    assert resp["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {resp}"
    # No execution artifact: TestState response never carries an executionArn field.
    assert "executionArn" not in resp, f"TestState must not surface an executionArn: {resp}"

    output = json.loads(resp["output"])
    assert output == {
        "orig": "value",
        "n": 1,
        "enrichment": {"processed": True, "stage": "probe"},
    }, f"unexpected merged output: {output}"

    # And the dry run left no state machine behind.
    after = _list_all_state_machine_names(ctx)
    assert after == before, (
        f"TestState must not create any persisted state machine: before={before} after={after}"
    )

    # A single-state definition that fails ASL validation (two states) must be rejected
    # server-side rather than silently accepted.
    multi_state_definition = json.dumps(
        {
            "StartAt": "A",
            "States": {
                "A": {"Type": "Pass", "Next": "B"},
                "B": {"Type": "Pass", "End": True},
            },
        }
    )
    code, message = _error(
        lambda: sfn.test_state(definition=multi_state_definition, input="{}")
    )
    assert code == "InvalidDefinition", (
        f"expected InvalidDefinition, got {code}"
    )
    assert message == "Missing required field: 'Type'", f"unexpected InvalidDefinition message: {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    because a target ACCEPTING an input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects this multi-state definition, but it SUCCEEDED and returned {result!r}"
    )


def _list_all_state_machine_names(ctx) -> set[str]:
    sfn = ctx.client("stepfunctions")
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        page = sfn.list_state_machines(**kwargs)
        names.update(sm["name"] for sm in page["stateMachines"])
        token = page.get("nextToken")
        if not token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
