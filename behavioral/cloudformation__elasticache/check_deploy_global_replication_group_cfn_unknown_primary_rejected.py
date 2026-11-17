"""deploy-global-replication-group-cfn-unknown-primary-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-global-replication-group-cfn-unknown-primary-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticache"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _wait_stack(cfn, stack_id: str, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _delete_stack(cfn, stack_id: str) -> None:
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, timeout_s=300.0)


def _failed_reason(cfn, stack_id: str, logical_id: str) -> str:
    events = _paginate(cfn, "describe_stack_events", "StackEvents", StackName=stack_id)
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _mask_per_call_fields(message: str) -> str:
    """``message`` with the handler's per-call Request ID and SDK attempt count blanked."""
    message = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <id>", message)
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message


def _handler_failure(reason: str) -> tuple:
    """``(masked message, HandlerErrorCode)`` of a registry-handler failure reason."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _mask_per_call_fields(m["message"]), m["code"]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation GlobalReplicationGroup naming a ReplicationGroupId that does not exist
    rolls the stack back, and no Global Datastore carrying its suffix ever exists."""
    cfn = ctx.client("cloudformation")
    ec = ctx.client("elasticache")

    bogus_primary = ctx.unique_name("sim2real-ecgrg-bogus-")
    suffix = ctx.unique_name("sim2realecgrgbadsfx").replace("-", "")[:16]
    stack_name = ctx.unique_name("sim2real-ecgrg-bad-stack-")
    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GlobalRepGroup": {
                "Type": "AWS::ElastiCache::GlobalReplicationGroup",
                "Properties": {
                    "GlobalReplicationGroupIdSuffix": suffix,
                    "Members": [
                        {
                            "ReplicationGroupId": bogus_primary,
                            "ReplicationGroupRegion": ctx.region,
                            "Role": "PRIMARY",
                        }
                    ],
                },
            }
        },
    })

    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": stack_name}]
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    got = _handler_failure(_failed_reason(cfn, stack_id, "GlobalRepGroup"))
    want = (
        f"Replication group '{bogus_primary}' not found (Service: ElastiCache, Status Code: 404, "
        "Request ID: <id>) (SDK Attempt Count: <n>)",
        "GeneralServiceException",
    )
    assert got == want, f"handler failure {got!r}, expected {want!r}"

    groups = _paginate(ec, "describe_global_replication_groups", "GlobalReplicationGroups")
    leaked = [g["GlobalReplicationGroupId"] for g in groups if g["GlobalReplicationGroupId"].endswith(suffix)]
    assert leaked == [], f"expected no Global Datastore carrying suffix {suffix!r}, found {leaked!r}"

    _delete_stack(cfn, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
