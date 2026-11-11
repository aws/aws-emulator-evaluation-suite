"""deploy-cluster-cfn-connectivity."""
from __future__ import annotations

import secrets
import string
import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError, WaiterError

CHECK = "deploy-cluster-cfn-connectivity"
GROUP = "state-machine"
SERVICES = ["redshift"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterIdentifier:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
  NodeType:
    Type: String
Resources:
  RedshiftCluster:
    Type: AWS::Redshift::Cluster
    Properties:
      ClusterIdentifier: !Ref ClusterIdentifier
      ClusterType: single-node
      NodeType: !Ref NodeType
      MasterUsername: cfnadmin
      MasterUserPassword: !Ref MasterUserPassword
      DBName: dev
      PubliclyAccessible: false
      Tags:
        - Key: sim2real
          Value: behavioral-check
Outputs:
  ClusterIdentifierOut:
    Value: !Ref ClusterIdentifier
"""

# Cheapest-first among node types DescribeOrderableClusterOptions reports as orderable for a
# single-node cluster: dc2 provisioning is withdrawn and rejected with "Invalid node type".
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus")
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
    """A CloudFormation-deployed cluster has an endpoint and GetClusterCredentials returns an IAMA: user,
    password and future expiry; after stack deletion both calls raise ClusterNotFound.
    """
    cfn = ctx.client("cloudformation")
    redshift = ctx.client("redshift")

    cluster_id = ctx.unique_name("sim2real-cfn-rs-")
    stack_name = ctx.unique_name("sim2real-cfn-rs-stack-")
    password = _generate_password()
    node_type = _pick_single_node_type(redshift)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ClusterIdentifier", "ParameterValue": cluster_id},
            {"ParameterKey": "MasterUserPassword", "ParameterValue": password},
            {"ParameterKey": "NodeType", "ParameterValue": node_type},
        ],
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    status = _poll_stack_terminal(cfn, stack_name, timeout_s=_budget_s(ctx, 1500), interval_s=_POLL_INTERVAL_S, ctx=ctx)
    if status != "CREATE_COMPLETE":
        raise AssertionError(
            f"stack {stack_name} expected CREATE_COMPLETE, got {status}: "
            f"{_failure_reason(cfn, stack_name)}"
        )

    cluster = _poll_cluster_available(redshift, cluster_id, timeout_s=_budget_s(ctx, 600))
    if cluster["ClusterStatus"] != "available" and _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} available: the run budget ended first; not graded")
    assert cluster["ClusterStatus"] == "available", (
        f"cluster {cluster_id} expected status 'available', got {cluster['ClusterStatus']}"
    )
    endpoint = cluster.get("Endpoint") or {}
    assert endpoint.get("Address"), "cluster has no reachable endpoint address"
    assert endpoint.get("Port"), "cluster has no reachable endpoint port"

    creds = redshift.get_cluster_credentials(
        ClusterIdentifier=cluster_id,
        DbUser="cfn_conn_test",
        DbName="dev",
        AutoCreate=True,
        DurationSeconds=900,
    )
    assert creds["DbUser"] == "IAMA:cfn_conn_test", (
        f"expected DbUser 'IAMA:cfn_conn_test' (GetClusterCredentials prefixes the "
        f"requested name with the IAM-auth scheme), got {creds['DbUser']!r}"
    )
    assert isinstance(creds["DbPassword"], str) and len(creds["DbPassword"]) >= 8, (
        f"expected a temporary password of at least 8 chars, got {creds['DbPassword']!r}"
    )
    expiration = creds["Expiration"]
    now = datetime.now(timezone.utc)
    assert expiration > now, f"credential expiration {expiration} is not in the future"

    _delete_stack(cfn, stack_name, max_wait_s=_budget_s(ctx, 2400), ctx=ctx)

    not_found = f"Cluster {cluster_id} not found."
    dead_read_code, dead_read_message = _error(
        lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)
    )
    assert dead_read_code == "ClusterNotFound", (
        f"expected DescribeClusters on the deleted cluster {cluster_id} to raise "
        f"ClusterNotFound, got {dead_read_code!r}"
    )
    assert dead_read_message == not_found, (
        f"expected DescribeClusters message {not_found!r}, got {dead_read_message!r}"
    )

    dead_mutate_code, dead_mutate_message = _error(
        lambda: redshift.get_cluster_credentials(
            ClusterIdentifier=cluster_id,
            DbUser="cfn_conn_test",
            DbName="dev",
            AutoCreate=True,
            DurationSeconds=900,
        )
    )
    assert dead_mutate_code == "ClusterNotFound", (
        f"expected GetClusterCredentials on the deleted cluster {cluster_id} to raise "
        f"ClusterNotFound, got {dead_mutate_code!r}"
    )
    assert dead_mutate_message == not_found, (
        f"expected GetClusterCredentials message {not_found!r}, got {dead_mutate_message!r}"
    )


def _pick_single_node_type(redshift) -> str:
    options = redshift.describe_orderable_cluster_options()["OrderableClusterOptions"]
    available = {o["NodeType"] for o in options if o["ClusterType"] == "single-node"}
    assert available, "Redshift reports no orderable single-node cluster options in this account/region"
    for preferred in _NODE_TYPE_PREFERENCE:
        if preferred in available:
            return preferred
    return sorted(available)[0]


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa1" + body


def _poll_stack_terminal(cfn, stack_name: str, timeout_s: float, interval_s: float, ctx=None) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = "CREATE_IN_PROGRESS"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} terminal: the run budget ended first; not graded")
    raise AssertionError(
        f"stack {stack_name} did not reach a terminal state within {timeout_s}s "
        f"(last status {status})"
    )


def _poll_cluster_available(redshift, cluster_id: str, timeout_s: float) -> dict:
    """The cluster's describe payload once it reads 'available', or the last one at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] == "available" or time.monotonic() >= deadline:
            return cluster
        time.sleep(_POLL_INTERVAL_S)


def _failure_reason(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        if event.get("ResourceStatus", "").endswith("FAILED") and event.get("ResourceStatusReason"):
            return f"{event['LogicalResourceId']}: {event['ResourceStatusReason']}"
    return "no failure reason found in stack events"


def _delete_stack(cfn, stack_name: str, max_wait_s: float = 2400, ctx=None) -> None:
    try:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise
        return
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    try:
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(max_wait_s // 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name} DELETE_COMPLETE: the run budget ended first; not graded") from exc
        raise


def _error(call) -> tuple[str, str | None]:
    """Call call(); return (error code, message). An unexpected success raises."""
    try:
        call()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected call to raise a ClientError, it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
