"""concurrent-flow-alias-name-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-flow-alias-name-race"
GROUP = "concurrency"
SERVICES = ["bedrock-agent"]

# Exercises name uniqueness under concurrent CreateFlowAlias calls.

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
    """Racing CreateFlowAlias calls with the identical alias name on one flow: exactly one wins."""
    role_arn = _create_flow_role(ctx)
    bedrock_agent = ctx.client("bedrock-agent")
    flow_id = bedrock_agent.create_flow(
        name=ctx.unique_name("sim2real-flow-"),
        executionRoleArn=role_arn,
        definition=_DEFINITION,
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: bedrock_agent.delete_flow(flowIdentifier=flow_id, skipResourceInUseCheck=True))

    bedrock_agent.prepare_flow(flowIdentifier=flow_id)
    prepared = _poll_until(
        lambda: bedrock_agent.get_flow(flowIdentifier=flow_id),
        lambda f: f["status"] in ("Prepared", "Failed"),
        timeout_s=90.0,
    )
    assert prepared["status"] == "Prepared", prepared
    version = bedrock_agent.create_flow_version(flowIdentifier=flow_id)["version"]
    ctx.on_cleanup(
        lambda: bedrock_agent.delete_flow_version(flowIdentifier=flow_id, flowVersion=version, skipResourceInUseCheck=True)
    )

    alias_name = ctx.unique_name("sim2real-race-alias-")
    racer_count = 5

    def _race(_i: int):
        try:
            resp = bedrock_agent.create_flow_alias(
                flowIdentifier=flow_id,
                name=alias_name,
                routingConfiguration=[{"flowVersion": version}],
                tags={"sim2real-check": CHECK},
            )
            return ("ok", resp["id"])
        except ClientError as err:
            return (err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_race, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] != "ok"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    assert all(code == "ConflictException" for code, _ in failures), failures

    winner_alias_id = successes[0][1]
    expected_conflict = (
        f"Couldn't perform CreateFlowAlias operation. The name {alias_name} already exists for id "
        f"{winner_alias_id}. Retry your request with a different name."
    )
    assert all(message == expected_conflict for _, message in failures), failures
    ctx.on_cleanup(lambda: _safe_delete_alias(bedrock_agent, flow_id, winner_alias_id))

    aliases = bedrock_agent.list_flow_aliases(flowIdentifier=flow_id)["flowAliasSummaries"]
    matching = [a for a in aliases if a["name"] == alias_name]
    assert len(matching) == 1, matching

    # The delete is already registered for cleanup; run it now and prove gone-and-unusable rather
    # than leaving it unasserted.
    bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=winner_alias_id)
    try:
        bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=winner_alias_id)
        raise AssertionError(f"expected {winner_alias_id} to be gone after delete_flow_alias")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", err.response["Error"]
        assert err.response["Error"].get("Message") == _not_found("GetFlowAlias", "FlowAlias"), err.response["Error"]

    remaining = bedrock_agent.list_flow_aliases(flowIdentifier=flow_id)["flowAliasSummaries"]
    assert not any(a["name"] == alias_name for a in remaining), remaining


def _safe_delete_alias(bedrock_agent, flow_id, alias_id):
    try:
        bedrock_agent.delete_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _not_found(operation, resource_type):
    return (
        f"Couldn't perform {operation} operation. Failed to retrieve resource type {resource_type} "
        "because it doesn't exist. Check the resource ID and retry your request."
    )


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
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
