"""deploy-cfn-replica-regions-serve-the-value-in-the-second-region-and-stack-delete-removes-both."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-replica-regions-serve-the-value-in-the-second-region-and-stack-delete-removes-both"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_DEPLOY_TIMEOUT_S = 420.0
# Deterministic second region, named in every failure message and reaped on every path.
_REPLICA_REGION_PRIMARY = "us-east-1"
_REPLICA_REGION_FALLBACK = "us-west-2"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation secret with ReplicaRegions is InSync in the second Region, serves the
    primary's plaintext under the same name and receives later writes; deleting the stack removes
    the secret from both Regions.
    """
    sm = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")
    replica_region = (
        _REPLICA_REGION_FALLBACK if ctx.region == _REPLICA_REGION_PRIMARY else _REPLICA_REGION_PRIMARY
    )
    assert replica_region != ctx.region, f"replica and primary both resolved to {ctx.region!r}"
    sm_replica = ctx.client("secretsmanager", region=replica_region)

    name = ctx.unique_name("sim2real-behav-cfnreplica-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Replicated": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {
                    "Name": name,
                    "SecretString": "replicated-by-template",
                    "ReplicaRegions": [{"Region": replica_region}],
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            }
        },
        "Outputs": {"Arn": {"Value": {"Ref": "Replicated"}}},
    }
    stack_name = ctx.unique_name("sim2real-behav-cfnreplica-")
    # Backstop first so LIFO runs it after the stack delete: whatever the stack left, in either
    # Region, is detached and force-deleted.
    ctx.on_cleanup(lambda: _reap_both(sm, sm_replica, name, replica_region))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    status = _wait_stack(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"the stack must deploy; it ended {status!r}: {_failures(cfn, stack_name)!r}"
    primary_arn = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"][0]["OutputValue"]

    row = _poll(
        lambda: _status(sm, primary_arn, replica_region),
        lambda st: st is not None and st.get("Status") != "InProgress",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"the {replica_region} replica to settle",
    )
    assert row.get("Status") == "InSync", f"the template's replica must reach InSync; got {row!r}"

    served = _poll(
        lambda: _read(sm_replica, name),
        lambda r: r[0] == "ok",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"the {replica_region} replica to serve the value",
    )
    assert served == ("ok", "replicated-by-template"), (
        f"the replica must serve the template's plaintext; got {served!r}"
    )
    replica_desc = sm_replica.describe_secret(SecretId=name)
    assert replica_desc.get("PrimaryRegion") == ctx.region, (
        f"the replica must name {ctx.region!r} as its primary; got {replica_desc.get('PrimaryRegion')!r}"
    )

    sm.put_secret_value(SecretId=primary_arn, SecretString="written-after-deploy")
    propagated = _poll(
        lambda: _read(sm_replica, name),
        lambda r: r == ("ok", "written-after-deploy"),
        timeout_s=180.0,
        interval_s=3.0,
        description=f"a primary write to reach the {replica_region} replica",
    )
    assert propagated == ("ok", "written-after-deploy"), f"the write must propagate; got {propagated!r}"

    _delete_stack(cfn, stack_name)
    primary_gone = _poll(
        lambda: _describe(sm, name),
        lambda r: r[0] != "ok",
        timeout_s=180.0,
        interval_s=3.0,
        description="the primary to be removed by the stack delete",
    )
    assert primary_gone == ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"after the stack delete the primary must be gone; got {primary_gone!r}"
    )
    replica_gone = _poll(
        lambda: _describe(sm_replica, name),
        lambda r: r[0] != "ok",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"the {replica_region} replica to be removed by the stack delete",
    )
    assert replica_gone == ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"after the stack delete the replica must be gone; got {replica_gone!r}"
    )


def _status(sm, secret_id, region):
    for row in sm.describe_secret(SecretId=secret_id).get("ReplicationStatus", []):
        if row["Region"] == region:
            return row
    return None


def _read(client, secret_id):
    try:
        return ("ok", client.get_secret_value(SecretId=secret_id)["SecretString"])
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))


def _describe(client, secret_id):
    try:
        d = client.describe_secret(SecretId=secret_id)
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    return ("ok", d.get("DeletedDate"))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _wait_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)


def _failures(cfn, stack_name):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _delete_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


def _reap_both(sm, sm_replica, name, region):
    """Detach and force-delete anything the stack left behind, in both Regions; a residue raises."""
    try:
        sm.remove_regions_from_replication(SecretId=name, RemoveReplicaRegions=[region])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "InvalidParameterException",
            "InvalidRequestException",
        ):
            raise
    for client in (sm_replica, sm):
        deadline = time.monotonic() + 120.0
        while True:
            try:
                client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    break
                if time.monotonic() >= deadline:
                    raise
                time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
