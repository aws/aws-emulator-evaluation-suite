"""deploy-opensearch-domain-cfn-behavioral."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-opensearch-domain-cfn-behavioral"
GROUP = "deploy"
SERVICES = ["opensearch"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A domain deployed via CloudFormation reaches ACTIVE and actually accepts index
    creation and reads through the OpenSearch control-plane index APIs, not merely
    CREATE_COMPLETE on the CloudFormation stack."""
    domain_name = _compliant_domain_name(ctx, "cfndom")
    stack_name = ctx.unique_name("sim2real-osd-stack-")
    cfn = ctx.client("cloudformation")
    opensearch = ctx.client("opensearch")

    template = json.dumps(
        {
            "Resources": {
                "Domain": {
                    "Type": "AWS::OpenSearchService::Domain",
                    "Properties": {
                        "DomainName": domain_name,
                        "EngineVersion": "OpenSearch_2.19",
                        "ClusterConfig": {
                            "InstanceType": "t3.small.search",
                            "InstanceCount": 1,
                            "DedicatedMasterEnabled": False,
                            "ZoneAwarenessEnabled": False,
                        },
                        "EBSOptions": {
                            "EBSEnabled": True,
                            "VolumeType": "gp3",
                            "VolumeSize": 10,
                        },
                        "Tags": [{"Key": "sim2real", "Value": "true"}],
                    },
                }
            }
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    stack_status = _wait_stack_settled(ctx, stack_name, timeout_s=3600.0)
    assert stack_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack_status}"

    domain_status = _wait_domain_active(ctx, domain_name, timeout_s=1200.0)
    assert domain_status["Created"] is True, f"expected Created=True, got {domain_status}"
    assert domain_status["Processing"] is False, f"expected Processing=False, got {domain_status}"

    index_name = "sim2real-idx-1"
    schema = {
        "settings": {"index": {"number_of_shards": "1", "number_of_replicas": "0"}},
        "mappings": {"properties": {"title": {"type": "text"}}},
    }
    create_resp = opensearch.create_index(
        DomainName=domain_name, IndexName=index_name, IndexSchema=schema
    )
    assert create_resp["Status"] == "CREATED", f"expected CreateIndex Status=CREATED, got {create_resp['Status']}"

    get_resp = opensearch.get_index(DomainName=domain_name, IndexName=index_name)
    returned_schema = get_resp["IndexSchema"]
    # The control-plane GetIndex mirrors the native OpenSearch GET /<index> response
    # shape, which nests everything under the index name -- unwrap it if present.
    if index_name in returned_schema:
        returned_schema = returned_schema[index_name]
    got_shards = str(returned_schema["settings"]["index"]["number_of_shards"])
    assert got_shards == "1", f"expected number_of_shards='1' via independent GetIndex, got {got_shards!r}"
    got_type = returned_schema["mappings"]["properties"]["title"]["type"]
    assert got_type == "text", f"expected mapping type 'text' via independent GetIndex, got {got_type!r}"



# ===== shared domain helpers =====


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack_settled(ctx, stack_name: str, timeout_s: float = 3600.0, interval_s: float = 2.0) -> str:
    """Poll DescribeStacks until the stack leaves CREATE_IN_PROGRESS; return its status."""
    cfn = ctx.client("cloudformation")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last != "CREATE_IN_PROGRESS":
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} settling: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_name} still CREATE_IN_PROGRESS after {timeout_s}s")


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1200.0, interval_s: float = 2.0):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last["Created"] and not last["Processing"]:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} reaching ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} did not reach ACTIVE in {timeout_s}s; last={last}")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 850}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
