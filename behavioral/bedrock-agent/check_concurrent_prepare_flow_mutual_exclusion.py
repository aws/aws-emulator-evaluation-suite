"""concurrent-prepare-flow-mutual-exclusion."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-prepare-flow-mutual-exclusion"
GROUP = "concurrency"
SERVICES = ["bedrock-agent"]

# Exercises mutual exclusion of concurrent PrepareFlow calls.

_DEFINITION = {
    "nodes": [
        {"name": "FlowInputNode", "type": "Input", "outputs": [{"name": "document", "type": "String"}]},
        {
            "name": "FlowOutputNode",
            "type": "Output",
            "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
        },
    ],
    "connections": [
        {
            "name": "InputToOutput",
            "source": "FlowInputNode",
            "target": "FlowOutputNode",
            "type": "Data",
            "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
        }
    ],
}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two PrepareFlow calls fired concurrently on the same stale DRAFT: only one may start Preparing."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    name = ctx.unique_name("sim2real-flow-")
    flow_id = bedrock_agent.create_flow(
        name=name, executionRoleArn=role_arn, definition=_DEFINITION, tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    # Warm-up prepare: gets the flow into a first Prepared state so the timed race below starts
    # from a real "stale DRAFT" (a second required prepare cycle), not the initial creation race.
    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing", "NotPrepared"),
        timeout_s=90.0,
    )

    # Force the DRAFT stale again so a second real prepare cycle is required.
    bedrock_agent.update_flow(
        flowIdentifier=flow_id, name=name, executionRoleArn=role_arn, definition=_DEFINITION, description="v2",
    )
    _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] == "NotPrepared",
        timeout_s=90.0,
    )

    def _race(_i: int):
        try:
            resp = bedrock_agent.prepare_flow(flowIdentifier=flow_id)
            return ("ok", resp["status"])
        except ClientError as err:
            return (err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_race, range(2)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] != "ok"]

    assert len(successes) == 1, f"expected exactly 1 racer to start preparation, got {len(successes)}: {results}"
    assert len(failures) == 1, f"expected exactly 1 racer to be rejected, got {len(failures)}: {results}"
    assert failures[0][0] == "ConflictException", failures
    assert failures[0][1] == (
        "Couldn't perform PrepareFlow operation. The resource is being updated by a concurrent "
        "request. Retry your request after the other request has completed."
    ), failures

    final = _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] not in ("Preparing",),
        timeout_s=90.0,
    )
    assert final["status"] == "Prepared", final["status"]


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_flow_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-flow-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="bedrock-flow-permissions",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": "*"}]}
        ),
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="bedrock-flow-permissions")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
