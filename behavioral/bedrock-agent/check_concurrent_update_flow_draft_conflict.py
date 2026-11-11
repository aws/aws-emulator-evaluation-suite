"""concurrent-update-flow-draft-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-flow-draft-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agent"]
_CONFLICT_MESSAGE = (
    "Couldn't perform UpdateFlow operation. The resource is being updated by a concurrent request. Retry your request after the other request has completed."
)

# Minimal valid flow: an Input node feeding straight into an Output node.
_DEFINITION = {
    "nodes": [
        {
            "name": "FlowInputNode",
            "type": "Input",
            "outputs": [{"name": "document", "type": "String"}],
        },
        {
            "name": "FlowOutputNode",
            "type": "Output",
            "inputs": [
                {"name": "document", "type": "String", "expression": "$.data"}
            ],
        },
    ],
    "connections": [
        {
            "type": "Data",
            "name": "InputToOutput",
            "source": "FlowInputNode",
            "target": "FlowOutputNode",
            "configuration": {
                "data": {"sourceOutput": "document", "targetInput": "document"}
            },
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent full-replacement UpdateFlow calls on one DRAFT, each with its own
    description, each succeed or lose with ConflictException, at least one succeeds, and the
    persisted description is a successful racer's, never a refused racer's."""
    bedrock = ctx.client("bedrock-agent")
    role_arn = _create_flow_execution_role(ctx)
    name = ctx.unique_name("sim2real-flow-lock-")

    created = _create_flow_with_role_propagation_retry(
        bedrock,
        name=name,
        executionRoleArn=role_arn,
        definition=_DEFINITION,
        description="initial description",
    )
    flow_id = created["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_flow(bedrock, flow_id))
    assert created["status"] == "NotPrepared", f"expected NotPrepared, got {created['status']!r}"

    barrier = threading.Barrier(2)
    desc_a = "racer-a-flow-description"
    desc_b = "racer-b-flow-description"

    def _racer(description):
        barrier.wait(timeout=10)
        try:
            bedrock.update_flow(
                flowIdentifier=flow_id,
                name=name,
                executionRoleArn=role_arn,
                definition=_DEFINITION,
                description=description,
            )
            return ("ok", None, None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return ("err", err.get("Code"), err.get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_racer, desc_a)
        fut_b = pool.submit(_racer, desc_b)
        result_a = fut_a.result()
        result_b = fut_b.result()

    results = [result_a, result_b]
    for status, code, message in results:
        if status == "ok":
            continue
        assert code == "ConflictException", (
            f"a racing UpdateFlow may only lose with ConflictException, got {code} ({message!r})"
        )
        assert message == _CONFLICT_MESSAGE, (
            f"ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}"
        )
    winners = [d for d, r in zip((desc_a, desc_b), results, strict=True) if r[0] == "ok"]
    assert winners, f"expected at least one racing UpdateFlow to succeed, got {results}"

    final = bedrock.get_flow(flowIdentifier=flow_id)
    assert final.get("description") in winners, (
        f"persisted description {final.get('description')!r} is not a successful racer's "
        f"({winners}); results={results}"
    )


def _best_effort_delete_flow(bedrock, flow_id):
    try:
        bedrock.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_flow_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-flow-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_flow_with_role_propagation_retry(bedrock, **kwargs) -> dict:
    deadline = time.monotonic() + 30.0
    while True:
        try:
            return bedrock.create_flow(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException") and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
