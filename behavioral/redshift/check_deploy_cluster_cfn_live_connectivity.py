"""deploy-cluster-cfn-live-connectivity."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cluster-cfn-live-connectivity"
GROUP = "state-machine"
SERVICES = ["redshift"]

_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed cluster reaches available and serves GetClusterCredentials; the stack
    then reaches DELETE_COMPLETE and the cluster is gone.
    """
    cfn = ctx.client("cloudformation")
    redshift = ctx.client("redshift")
    ec2 = ctx.client("ec2")

    stack_name = ctx.unique_name("sim2real-rscfn-")
    cluster_id = ctx.unique_name("sim2real-rscl-").lower()
    password = _master_password()
    # VPC-only accounts (every current account) require Redshift to be told which
    # subnet to place the cluster in; it goes in a subnet of the run's shared network.
    subnet_id = _find_subnet(ec2, ctx=ctx)
    # dc2.large is not orderable in every account/region (new accounts are steered to
    # RA3); ask the target what it will actually accept rather than hardcoding a node
    # type and letting CloudFormation roll back on "Invalid node type".
    node_type = _node_type(redshift, cluster_type="single-node")

    template = {
        "Parameters": {
            "ClusterIdentifierParam": {"Type": "String"},
            "MasterUserPasswordParam": {"Type": "String", "NoEcho": True},
            "SubnetIdParam": {"Type": "AWS::EC2::Subnet::Id"},
            "NodeTypeParam": {"Type": "String"},
        },
        "Resources": {
            "ClusterSubnetGroup": {
                "Type": "AWS::Redshift::ClusterSubnetGroup",
                "Properties": {
                    "Description": "sim2real-rscfn-live-connectivity",
                    "SubnetIds": [{"Ref": "SubnetIdParam"}],
                },
            },
            "RedshiftCluster": {
                "Type": "AWS::Redshift::Cluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "ClusterIdentifier": {"Ref": "ClusterIdentifierParam"},
                    "ClusterType": "single-node",
                    "NodeType": {"Ref": "NodeTypeParam"},
                    "MasterUsername": "cfnadmin",
                    "MasterUserPassword": {"Ref": "MasterUserPasswordParam"},
                    "DBName": "dev",
                    "ClusterSubnetGroupName": {"Ref": "ClusterSubnetGroup"},
                    "PubliclyAccessible": False,
                },
            },
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[
            {"ParameterKey": "ClusterIdentifierParam", "ParameterValue": cluster_id},
            {"ParameterKey": "MasterUserPasswordParam", "ParameterValue": password},
            {"ParameterKey": "SubnetIdParam", "ParameterValue": subnet_id},
            {"ParameterKey": "NodeTypeParam", "ParameterValue": node_type},
        ],
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )

    def _cleanup() -> None:
        # Best-effort fallback only: the in-body teardown below already issues and
        # confirms the delete. This just guards the case where the check raises
        # before reaching that point. Idempotent -- a stack that is already gone
        # (or already mid-delete) must not turn a passing run into a cleanup error.
        try:
            cfn.delete_stack(StackName=stack_name)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)

    final_status = _poll_stack_terminal(cfn, stack_name, timeout_s=_budget_s(ctx, 900), ctx=ctx)
    assert final_status == "CREATE_COMPLETE", (
        f"stack {stack_name} did not reach CREATE_COMPLETE (got {final_status}): "
        f"{_stack_failure_reasons(cfn, stack_name)}"
    )

    cluster_status = _poll_cluster_status(redshift, cluster_id, timeout_s=_budget_s(ctx, 180), ctx=ctx)
    assert cluster_status == "available", (
        f"cluster {cluster_id} did not become available after stack completion "
        f"(got {cluster_status})"
    )

    request_time = datetime.now(timezone.utc)
    duration_s = 900
    creds = redshift.get_cluster_credentials(
        ClusterIdentifier=cluster_id,
        DbUser="cfntestuser",
        AutoCreate=True,
        DurationSeconds=duration_s,
    )
    assert creds["DbUser"] == "IAMA:cfntestuser", (
        f"expected AutoCreate to issue DbUser 'IAMA:cfntestuser', got {creds['DbUser']!r}"
    )
    assert isinstance(creds["DbPassword"], str) and len(creds["DbPassword"]) >= 8, (
        f"expected a non-trivial temporary password, got {creds['DbPassword']!r}"
    )
    # Two-sided: Expiration must be in the future AND honor the requested DurationSeconds.
    assert creds["Expiration"] > datetime.now(timezone.utc), (
        f"credential expiration {creds['Expiration']} is not in the future"
    )
    assert creds["Expiration"] <= request_time + timedelta(seconds=duration_s + 60), (
        f"credential expiration {creds['Expiration']} exceeds the requested "
        f"DurationSeconds={duration_s} (issued at {request_time}, +60s slack)"
    )

    # Teardown is asserted: the cluster must actually be gone, not just the delete accepted.
    cfn.delete_stack(StackName=stack_name)
    delete_status = _poll_stack_terminal(
        cfn, stack_name, timeout_s=_budget_s(ctx, 900), terminal={"DELETE_COMPLETE", "DELETE_FAILED"},
        missing_is="DELETE_COMPLETE", ctx=ctx,
    )
    assert delete_status == "DELETE_COMPLETE", (
        f"stack {stack_name} did not reach DELETE_COMPLETE (got {delete_status})"
    )

    try:
        redshift.describe_clusters(ClusterIdentifier=cluster_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ClusterNotFound", (
            f"expected ClusterNotFound after stack deletion, got {code!r}: {exc}"
        )
        message = exc.response.get("Error", {}).get("Message")
        expected = f"Cluster {cluster_id} not found."
        assert message == expected, f"expected {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"cluster {cluster_id} still describable after stack DELETE_COMPLETE"
        )


def _master_password() -> str:
    import secrets

    return f"CfnAdm1n{secrets.token_hex(4)}"


def _stack_failure_reasons(cfn, stack_name: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in events
        if "FAILED" in e.get("ResourceStatus", "")
    ]


_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this account/region --
    dc2.large is not always orderable (new accounts are steered to RA3), so ask the
    target what it will actually accept rather than hardcoding one and letting
    CloudFormation roll back on 'Invalid node type'."""
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type!r} node types in this region")
        chosen = sorted(available)[0]
    return chosen


def _find_subnet(ec2, *, ctx) -> str:
    """Prefer the run's shared network; fall back to any VPC with a subnet. Raises
    a clear AssertionError (not a bare IndexError that reads as an environment
    problem) if this account has neither."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"VPC {vpc_id} has no subnets to place the Redshift cluster in")
    return subnets[0]["SubnetId"]


_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


def _poll_stack_terminal(
    cfn, stack_name: str, timeout_s: float, *, terminal: set[str] | None = None,
    missing_is: str | None = None, ctx=None,
) -> str:
    """Poll DescribeStacks until *stack_name* reaches one of *terminal* (default: the
    create-terminal set). Raises on timeout rather than returning the last
    in-progress value: a truncated poll must never be mistaken for a result.
    If *missing_is* is set, a ValidationError for "stack does not exist" (CFN
    eventually stops listing a deleted stack) is treated as that status.
    """
    terminal = terminal or _CREATE_TERMINAL
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if missing_is is not None and "does not exist" in str(exc):
                return missing_is
            raise
        status = stacks[0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(_POLL_INTERVAL_S)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} in {sorted(terminal)}: the run budget ended first; not graded")
    raise AssertionError(
        f"stack {stack_name} did not reach a terminal state {sorted(terminal)} within "
        f"{timeout_s}s (last status={status!r})"
    )


def _poll_cluster_status(redshift, cluster_id: str, timeout_s: float, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        except ClientError as exc:
            status = f"<describe_clusters error: {exc}>"
            time.sleep(_POLL_INTERVAL_S)
            continue
        status = clusters[0]["ClusterStatus"]
        if status == "available":
            return status
        time.sleep(_POLL_INTERVAL_S)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} available: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} did not become available within {timeout_s}s "
        f"(last status={status!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
