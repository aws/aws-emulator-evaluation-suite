"""stop-flow-execution-concurrent-race."""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-flow-execution-concurrent-race"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


_INPUT_NODE = "FlowInputNode"
_OUTPUT_NODE = "FlowOutputNode"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartFlowExecution followed by two concurrent StopFlowExecution calls:
    exactly one racer wins (Aborted, confirmed by GetFlowExecution), and the
    loser and a later third stop are both rejected with ConflictException and its exact message.
    """
    role_arn = _create_flow_execution_role(ctx)
    flow_id = _create_passthrough_flow(ctx, role_arn)
    alias_id = _prepare_and_deploy_flow(ctx, flow_id)

    runtime = ctx.client("bedrock-agent-runtime")
    observed_real_race = False
    last_outcomes: dict[str, tuple[str, Any]] = {}
    winning_execution_arn = ""
    winning_exec_name = ""
    for _attempt in range(8):
        exec_name = f"exec-{uuid.uuid4().hex[:12]}"
        execution_arn = runtime.start_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            flowExecutionName=exec_name,
            inputs=[
                {
                    "nodeName": _INPUT_NODE,
                    "nodeOutputName": "document",
                    "content": {"document": "race-me"},
                }
            ],
        )["executionArn"]

        outcomes = _race_stop_calls(runtime, flow_id, alias_id, execution_arn)
        last_outcomes = outcomes
        successes = [tag for tag, (kind, _) in outcomes.items() if kind == "ok"]
        failures = [tag for tag, (kind, _) in outcomes.items() if kind == "error"]

        if (
            len(successes) == 1
            and len(failures) == 1
            and outcomes[failures[0]][1][0] == "ConflictException"
        ):
            observed_real_race = True
            winning_execution_arn = execution_arn
            winning_exec_name = exec_name
            winner_tag = successes[0]
            assert outcomes[winner_tag][1]["status"] == "Aborted", (
                f"expected the winning racer's StopFlowExecution to report Aborted, "
                f"got {outcomes[winner_tag][1]['status']!r}"
            )
            loser_code, loser_message = outcomes[failures[0]][1]
            expected_loser_message = (
                f"Flow execution {exec_name} is in Aborted status and cannot be aborted."
            )
            assert loser_message == expected_loser_message, (
                f"expected the losing racer's StopFlowExecution to fail with message "
                f"{expected_loser_message!r}, got {loser_message!r}"
            )
            break

    if not observed_real_race:
        raise AssertionError(
            "could not land the concurrent-stop race in 8 attempts: this "
            "minimal passthrough flow execution always finished (or both "
            "racers already found it terminal) before the two "
            f"StopFlowExecution calls could contend with each other; last "
            f"observed outcomes={last_outcomes}. Closes with a "
            "purpose-built slow-node flow fixture that stays Running "
            "reliably for the duration of the race."
        )

    # the effect is exactly one winner: the execution actually reached the
    # Aborted terminal state, not left Running and not double-processed.
    final = runtime.get_flow_execution(
        flowIdentifier=flow_id,
        flowAliasIdentifier=alias_id,
        executionIdentifier=winning_execution_arn,
    )
    assert final["status"] == "Aborted", (
        f"expected GetFlowExecution to confirm the winning stop reached Aborted, "
        f"got {final['status']!r}"
    )

    # stopping an execution that is already in a terminal state is consistently
    # rejected, never silently accepted a second time.
    second_stop_code, second_stop_message = _error_code_and_message_from_call(
        lambda: runtime.stop_flow_execution(
            flowIdentifier=flow_id,
            flowAliasIdentifier=alias_id,
            executionIdentifier=winning_execution_arn,
        )
    )
    assert second_stop_code == "ConflictException", (
        f"expected a third StopFlowExecution on the now-terminal execution to be "
        f"rejected with ConflictException, got code={second_stop_code!r}"
    )
    expected_second_stop_message = (
        f"Flow execution {winning_exec_name} is in Aborted status and cannot be aborted."
    )
    assert second_stop_message == expected_second_stop_message, (
        f"expected message {expected_second_stop_message!r}, got {second_stop_message!r}"
    )


def _race_stop_calls(
    runtime, flow_id: str, alias_id: str, execution_arn: str
) -> dict[str, tuple[str, Any]]:
    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def _stop(tag: str) -> None:
        barrier.wait()
        try:
            resp = runtime.stop_flow_execution(
                flowIdentifier=flow_id,
                flowAliasIdentifier=alias_id,
                executionIdentifier=execution_arn,
            )
            results[tag] = ("ok", resp)
        except Exception as exc:  # noqa: BLE001
            results[tag] = ("error", _error_code_and_message(exc))

    threads = [threading.Thread(target=_stop, args=(tag,)) for tag in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def _error_code(exc: Exception) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code")
    return None


def _error_code_and_message(exc: Exception) -> tuple[str | None, str | None]:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return None, None


def _error_code_and_message_from_call(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _create_flow_execution_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-flow-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    try:
        role = iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
        )["Role"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            "could not create the IAM role needed to run a Bedrock flow "
            f"execution ({_error_code(exc) or exc}); this check needs "
            "iam:CreateRole in the test account."
        ) from exc
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_passthrough_flow(ctx, role_arn: str) -> str:
    agent = ctx.client("bedrock-agent")
    flow_name = ctx.unique_name("sim2real-flow-")
    definition = {
        "nodes": [
            {
                "name": _INPUT_NODE,
                "type": "Input",
                "outputs": [{"name": "document", "type": "String"}],
                "configuration": {"input": {}},
            },
            {
                "name": _OUTPUT_NODE,
                "type": "Output",
                "inputs": [
                    {"name": "document", "type": "String", "expression": "$.data"}
                ],
                "configuration": {"output": {}},
            },
        ],
        "connections": [
            {
                "name": "InputToOutput",
                "source": _INPUT_NODE,
                "target": _OUTPUT_NODE,
                "type": "Data",
                "configuration": {
                    "data": {"sourceOutput": "document", "targetInput": "document"}
                },
            }
        ],
    }

    # a freshly-created IAM role can take a few seconds to become
    # assumable by the bedrock.amazonaws.com service principal; poll for
    # that specific, documented eventual-consistency window rather than
    # sleeping a fixed duration.
    deadline = time.monotonic() + 30
    flow = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            flow = agent.create_flow(
                name=flow_name, executionRoleArn=role_arn, definition=definition
            )
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if _error_code(exc) not in ("ValidationException", "AccessDeniedException"):
                raise
            time.sleep(2)
    if flow is None:
        raise AssertionError(
            "CreateFlow never accepted the freshly-created execution role "
            f"within 30s (last error={_error_code(last_exc) if last_exc else None}); "
            "IAM role propagation for the bedrock.amazonaws.com principal "
            "did not complete in time in this environment."
        )
    flow_id = flow["id"]
    ctx.on_cleanup(lambda: _delete_flow(ctx, flow_id))
    return flow_id


def _delete_flow(ctx, flow_id: str) -> None:
    agent = ctx.client("bedrock-agent")
    try:
        agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _prepare_and_deploy_flow(ctx, flow_id: str) -> str:
    agent = ctx.client("bedrock-agent")
    agent.prepare_flow(flowIdentifier=flow_id)

    deadline = time.monotonic() + 60
    status = None
    while time.monotonic() < deadline:
        status = agent.get_flow(flowIdentifier=flow_id)["status"]
        if status in ("Prepared", "Failed"):
            break
        time.sleep(2)
    if status != "Prepared":
        raise AssertionError(
            f"flow never reached Prepared status within 60s (last status={status})",
        )

    version = agent.create_flow_version(flowIdentifier=flow_id)["version"]
    alias_name = ctx.unique_name("sim2real-alias-")
    alias = agent.create_flow_alias(
        flowIdentifier=flow_id,
        name=alias_name,
        routingConfiguration=[{"flowVersion": version}],
    )
    alias_id = alias["id"]
    ctx.on_cleanup(lambda: _delete_alias(ctx, flow_id, alias_id))
    return alias_id


def _delete_alias(ctx, flow_id: str, alias_id: str) -> None:
    agent = ctx.client("bedrock-agent")
    try:
        agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
