"""cfn-redshift-cluster-invalid-iam-role-arn-rejected."""

from __future__ import annotations

import json
import re
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-cluster-invalid-iam-role-arn-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
    }
)
_POLL_S = 2.0
_DELETE_BUDGET_S = 900.0
#: One cheap current-generation node type that runs as a single node; asserted orderable first.
_NODE_TYPE = "ra3.large"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=900.0):
    """Poll DescribeStacks by StackId until a status in ``terminal``; return it."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(_POLL_S)


def stack_events(cf, stack_id):
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events[::-1]


def failure_reasons(cf, stack_id):
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in stack_events(cf, stack_id)
        if e["ResourceStatus"].endswith("FAILED")
    ]


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId whatever its state; raise unless it ends DELETE_COMPLETE."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        wait_stack(ctx, cf, stack_id, _TERMINAL, _DELETE_BUDGET_S)
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
    if status != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} delete ended {status!r}: {failure_reasons(cf, stack_id)!r}"
        )


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa1" + body


def _assert_orderable(rs) -> None:
    """``_NODE_TYPE`` is orderable as a single-node cluster here, read across every page."""
    pages = rs.get_paginator("describe_orderable_cluster_options").paginate(NodeType=_NODE_TYPE)
    types = {o["ClusterType"] for page in pages for o in page["OrderableClusterOptions"]}
    assert "single-node" in types, f"{_NODE_TYPE} is not orderable single-node here: {types!r}"


_BAD_ROLE_VALUE = "not-an-arn-at-all"


def failed_reason(cf, stack_id, logical_id, status="CREATE_FAILED"):
    """The reason on the single row of logical_id with ResourceStatus == status."""
    rows = [
        e.get("ResourceStatusReason")
        for e in stack_events(cf, stack_id)
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text: str) -> str:
    """text with only Request ID, RequestToken and SDK attempt count masked."""
    text = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    return re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)


def _template() -> str:
    return json.dumps(
        {
            "Parameters": {
                "ClusterIdentifierParam": {"Type": "String"},
                "AdminUserPasswordParam": {"Type": "String", "NoEcho": True},
                "IamRoleArnParam": {"Type": "String"},
            },
            "Resources": {
                "Cluster": {
                    "Type": "AWS::Redshift::Cluster",
                    "DeletionPolicy": "Delete",
                    "UpdateReplacePolicy": "Delete",
                    "Properties": {
                        "ClusterIdentifier": {"Ref": "ClusterIdentifierParam"},
                        "ClusterType": "single-node",
                        "NodeType": _NODE_TYPE,
                        "MasterUsername": "s2rcfnadmin",
                        "MasterUserPassword": {"Ref": "AdminUserPasswordParam"},
                        "DBName": "dev",
                        "PubliclyAccessible": False,
                        "IamRoles": [{"Ref": "IamRoleArnParam"}],
                        "Tags": [{"Key": "sim2real", "Value": "behavioral-check"}],
                    },
                },
            },
        }
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::Redshift::Cluster whose IamRoles holds a value that is not an IAM role
    ARN rolls back with Redshift's exact not-valid reason, and no cluster with its identifier
    exists.
    """
    cfn = ctx.client("cloudformation")
    rs = ctx.client("redshift")

    _assert_orderable(rs)
    bad_cluster_id = ctx.unique_name("sim2real-cfnrs-iambad-").lower()
    stack_name = ctx.unique_name("sim2real-cfnrs-iamrej-")
    bad_stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Parameters=[
            {"ParameterKey": "ClusterIdentifierParam", "ParameterValue": bad_cluster_id},
            {"ParameterKey": "AdminUserPasswordParam", "ParameterValue": _password()},
            {"ParameterKey": "IamRoleArnParam", "ParameterValue": _BAD_ROLE_VALUE},
        ],
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )["StackId"]
    ctx.on_cleanup(lambda: delete_stack(ctx, cfn, bad_stack_id))

    bad_status = wait_stack(ctx, cfn, bad_stack_id, timeout_s=300)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"bad stack {bad_stack_id} ended {bad_status!r}: {failure_reasons(cfn, bad_stack_id)!r}"
    )
    reason = masked(failed_reason(cfn, bad_stack_id, "Cluster"))
    expected = (
        'Resource handler returned message: "The IAM role not-an-arn-at-all is not valid. '
        "The IAM role must delegate access to an Amazon Redshift account. "
        '(Service: Redshift, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <token>, HandlerErrorCode: GeneralServiceException)"
    )
    assert reason == expected, f"expected reason {expected!r}, got {reason!r}"
    got = _error(lambda: rs.describe_clusters(ClusterIdentifier=bad_cluster_id))
    want = ("ClusterNotFound", f"Cluster {bad_cluster_id} not found.")
    assert got == want, f"DescribeClusters of the rejected cluster: {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
