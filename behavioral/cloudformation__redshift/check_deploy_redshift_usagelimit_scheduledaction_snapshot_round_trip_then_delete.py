"""deploy-redshift-usagelimit-scheduledaction-snapshot-round-trip-then-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-redshift-usagelimit-scheduledaction-snapshot-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "redshift"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

def _template(subnet_ids, sg_id, cluster_id, subnet_group_name, scheduled_action_name,
              snapshot_id, with_children=True):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "scheduler.redshift.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    pause_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "redshift:PauseCluster",
            "Resource": {
                "Fn::Sub": "arn:${AWS::Partition}:redshift:${AWS::Region}:${AWS::AccountId}"
                           ":cluster:${RedshiftCluster}"
            },
        }],
    }
    resources = {
        "ClusterSubnetGroup": {
            "Type": "AWS::Redshift::ClusterSubnetGroup",
            "Properties": {
                "Description": subnet_group_name,
                "SubnetIds": subnet_ids,
            },
        },
        "RedshiftCluster": {
            "Type": "AWS::Redshift::Cluster",
            "Properties": {
                "ClusterIdentifier": cluster_id,
                "ClusterType": "single-node",
                "NodeType": "ra3.large",
                "MasterUsername": "s2radmin",
                "ManageMasterPassword": True,
                "DBName": "dev",
                "ClusterSubnetGroupName": {"Ref": "ClusterSubnetGroup"},
                "VpcSecurityGroupIds": [sg_id],
                "PubliclyAccessible": False,
            },
        },
    }
    children = {
        "UsageLimit": {
            "Type": "AWS::Redshift::UsageLimit",
            "Properties": {
                "ClusterIdentifier": {"Ref": "RedshiftCluster"},
                "FeatureType": "spectrum",
                "LimitType": "data-scanned",
                "Amount": 1,
                "BreachAction": "log",
            },
        },
        "SchedulerRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": trust,
                "Policies": [{"PolicyName": "pause-cluster", "PolicyDocument": pause_policy}],
            },
        },
        "ScheduledAction": {
            "Type": "AWS::Redshift::ScheduledAction",
            "Properties": {
                "ScheduledActionName": scheduled_action_name,
                "TargetAction": {"PauseCluster": {"ClusterIdentifier": {"Ref": "RedshiftCluster"}}},
                "Schedule": "at(2099-12-31T23:59:00)",
                "IamRole": {"Fn::GetAtt": ["SchedulerRole", "Arn"]},
                "Enable": False,
            },
        },
        "Snapshot": {
            "Type": "AWS::Redshift::Snapshot",
            "Properties": {
                "SnapshotIdentifier": snapshot_id,
                "ClusterIdentifier": {"Ref": "RedshiftCluster"},
                "ManualSnapshotRetentionPeriod": 1,
            },
        },
    }
    outputs = {
        "ClusterRef": {"Value": {"Ref": "RedshiftCluster"}},
        "SubnetGroupRef": {"Value": {"Ref": "ClusterSubnetGroup"}},
    }
    child_outputs = {
        "RoleArn": {"Value": {"Fn::GetAtt": ["SchedulerRole", "Arn"]}},
        "UsageLimitRef": {"Value": {"Ref": "UsageLimit"}},
        "UsageLimitArnAtt": {"Value": {"Fn::GetAtt": ["UsageLimit", "Arn"]}},
        "UsageLimitId": {"Value": {"Fn::GetAtt": ["UsageLimit", "UsageLimitId"]}},
        "ScheduledActionRef": {"Value": {"Ref": "ScheduledAction"}},
        "ScheduledActionState": {"Value": {"Fn::GetAtt": ["ScheduledAction", "State"]}},
        "SnapshotRef": {"Value": {"Ref": "Snapshot"}},
        "SnapshotArnAtt": {"Value": {"Fn::GetAtt": ["Snapshot", "SnapshotArn"]}},
        "SnapshotStatus": {"Value": {"Fn::GetAtt": ["Snapshot", "Status"]}},
    }
    if with_children:
        resources.update(children)
        outputs.update(child_outputs)
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _own_tags(raw_tags):
    """Tags minus the ``aws:`` system tags, as a {key: value} dict."""
    return {t["Key"]: t["Value"] for t in raw_tags if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation UsageLimit, ScheduledAction and Snapshot on a Redshift cluster read back.

    Every templated property, Ref and GetAtt match Redshift; an update dropping the three children
    removes each while the same cluster answers, and the stack delete removes the cluster.
    """
    cfn = ctx.client("cloudformation")
    redshift = ctx.client("redshift")

    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    sg_id = net.security_group_id

    stack = ctx.unique_name("sim2real-cfnrs-")
    cluster_id = ctx.unique_name("sim2real-rscl-").lower()
    subnet_group_name = ctx.unique_name("sim2real-rscsg-").lower()
    scheduled_action_name = ctx.unique_name("sim2real-rssa-").lower()
    snapshot_id = ctx.unique_name("sim2real-rssnap-").lower()
    names = (subnet_ids, sg_id, cluster_id, subnet_group_name, scheduled_action_name, snapshot_id)

    stack_id = create_stack(ctx, cfn, stack, _template(*names), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=1500.0)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # --- Subnet group: Ref == the independently listed group carrying the templated Description.
    groups = [g for g in paginate(redshift, "describe_cluster_subnet_groups", "ClusterSubnetGroups")
              if g.get("Description") == subnet_group_name]
    assert [g["ClusterSubnetGroupName"] for g in groups] == [out["SubnetGroupRef"]], (
        f"subnet groups described {subnet_group_name!r}: {groups!r}, Ref {out['SubnetGroupRef']!r}"
    )
    got_subnets = sorted(s["SubnetIdentifier"] for s in groups[0]["Subnets"])
    assert got_subnets == sorted(subnet_ids), f"subnet group subnets {got_subnets!r}"
    assert _own_tags(groups[0].get("Tags", [])) == {"sim2real": stack}, (
        f"subnet group tags {groups[0].get('Tags')!r}, expected the propagated stack tag"
    )

    # --- Cluster: Ref == the cluster an independent paginated listing holds under the name.
    clusters = [c for c in paginate(redshift, "describe_clusters", "Clusters")
                if c["ClusterIdentifier"] == cluster_id]
    assert len(clusters) == 1 and out["ClusterRef"] == cluster_id, (
        f"Ref RedshiftCluster {out['ClusterRef']!r}; clusters named {cluster_id!r}: {clusters!r}"
    )
    cluster = clusters[0]
    got_cluster = {
        "NodeType": cluster["NodeType"], "NumberOfNodes": cluster["NumberOfNodes"],
        "MasterUsername": cluster["MasterUsername"], "DBName": cluster["DBName"],
        "ClusterSubnetGroupName": cluster["ClusterSubnetGroupName"],
        "VpcSecurityGroupIds": [g["VpcSecurityGroupId"] for g in cluster["VpcSecurityGroups"]],
        "PubliclyAccessible": cluster["PubliclyAccessible"],
    }
    assert got_cluster == {
        "NodeType": "ra3.large", "NumberOfNodes": 1, "MasterUsername": "s2radmin",
        "DBName": "dev", "ClusterSubnetGroupName": out["SubnetGroupRef"],
        "VpcSecurityGroupIds": [sg_id], "PubliclyAccessible": False,
    }, f"cluster properties {got_cluster!r}"
    # The managed admin password lives in a Secrets Manager secret of this account and region.
    secret_arn = cluster.get("MasterPasswordSecretArn", "")
    secret_re = rf"arn:{partition}:secretsmanager:{ctx.region}:{ctx.account}:secret:\S+"
    assert re.fullmatch(secret_re, secret_arn), f"managed password secret ARN {secret_arn!r}"
    assert _own_tags(cluster.get("Tags", [])) == {"sim2real": stack}, (
        f"cluster tags {cluster.get('Tags')!r}, expected the propagated stack tag"
    )
    created = cluster["ClusterCreateTime"]

    # --- UsageLimit: independent read by (ClusterIdentifier, FeatureType); Redshift returns no
    # ARN for a usage limit, so Ref == GetAtt Arn and GetAtt UsageLimitId == the read's id.
    assert out["UsageLimitRef"] == out["UsageLimitArnAtt"], (
        f"Ref UsageLimit {out['UsageLimitRef']!r} != GetAtt Arn {out['UsageLimitArnAtt']!r}"
    )
    limits = paginate(redshift, "describe_usage_limits", "UsageLimits",
                      ClusterIdentifier=cluster_id, FeatureType="spectrum")
    assert len(limits) == 1, f"expected one spectrum usage limit on {cluster_id}, got {limits!r}"
    limit = limits[0]
    assert limit["UsageLimitId"] == out["UsageLimitId"], (
        f"independent read UsageLimitId {limit['UsageLimitId']!r} != GetAtt {out['UsageLimitId']!r}"
    )
    got_limit = {k: limit[k] for k in ("ClusterIdentifier", "FeatureType", "LimitType", "Amount",
                                       "BreachAction")}
    assert got_limit == {
        "ClusterIdentifier": cluster_id, "FeatureType": "spectrum", "LimitType": "data-scanned",
        "Amount": 1, "BreachAction": "log",
    }, f"usage limit properties {got_limit!r}"
    assert _own_tags(limit.get("Tags", [])) == {"sim2real": stack}, (
        f"usage limit tags {limit.get('Tags')!r}, expected the propagated stack tag"
    )

    # --- ScheduledAction: Ref echoes the name; an independent list by TargetActionType finds it
    # with the templated schedule, target, role and the disabled state.
    assert out["ScheduledActionRef"] == scheduled_action_name, (
        f"Ref ScheduledAction {out['ScheduledActionRef']!r} != {scheduled_action_name!r}"
    )
    actions = paginate(redshift, "describe_scheduled_actions", "ScheduledActions",
                       TargetActionType="PauseCluster")
    matches = [a for a in actions if a["ScheduledActionName"] == scheduled_action_name]
    assert len(matches) == 1, f"scheduled actions named {scheduled_action_name!r}: {matches!r}"
    action = matches[0]
    assert action["State"] == out["ScheduledActionState"] == "DISABLED", (
        f"State {action['State']!r}, GetAtt {out['ScheduledActionState']!r}, expected 'DISABLED'"
    )
    got_action = (action["Schedule"], action["TargetAction"], action["IamRole"])
    want_action = ("at(2099-12-31T23:59:00)", {"PauseCluster": {"ClusterIdentifier": cluster_id}},
                   out["RoleArn"])
    assert got_action == want_action, f"scheduled action {got_action!r} != {want_action!r}"

    # --- Snapshot: Ref and GetAtt SnapshotArn both equal the independently read SnapshotArn.
    assert out["SnapshotRef"] == out["SnapshotArnAtt"], (
        f"Ref Snapshot {out['SnapshotRef']!r} != GetAtt SnapshotArn {out['SnapshotArnAtt']!r}"
    )
    snaps = paginate(redshift, "describe_cluster_snapshots", "Snapshots",
                     ClusterIdentifier=cluster_id, SnapshotType="manual")
    smatches = [s for s in snaps if s["SnapshotIdentifier"] == snapshot_id]
    assert len(smatches) == 1, f"expected one manual snapshot {snapshot_id!r}, got {smatches!r}"
    snap = smatches[0]
    assert snap["SnapshotArn"] == out["SnapshotRef"], (
        f"independent read SnapshotArn {snap['SnapshotArn']!r} != Ref {out['SnapshotRef']!r}"
    )
    assert snap["Status"] == out["SnapshotStatus"] == "available", (
        f"Status {snap['Status']!r}, GetAtt {out['SnapshotStatus']!r}, expected 'available'"
    )
    got_snap = {k: snap[k] for k in ("ClusterIdentifier", "ManualSnapshotRetentionPeriod")}
    assert got_snap == {"ClusterIdentifier": cluster_id, "ManualSnapshotRetentionPeriod": 1}, (
        f"snapshot properties {got_snap!r}"
    )
    assert _own_tags(snap.get("Tags", [])) == {"sim2real": stack}, (
        f"snapshot tags {snap.get('Tags')!r}, expected the propagated stack tag"
    )

    # --- Children before the parent: an update dropping them removes each through Redshift while
    # the same cluster (ClusterCreateTime) still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*names, with_children=False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    remaining = redshift.describe_usage_limits(UsageLimitId=out["UsageLimitId"])["UsageLimits"]
    assert remaining == [], f"usage limit {out['UsageLimitId']} still listed: {remaining!r}"
    gone = (
        "ScheduledActionNotFound",
        f"The scheduled action {scheduled_action_name} was not found.",
    )
    expect_error(
        lambda: redshift.describe_scheduled_actions(ScheduledActionName=scheduled_action_name),
        *gone,
    )
    gone = ("ClusterSnapshotNotFound", f"Snapshot {snapshot_id} not found.")
    expect_error(lambda: redshift.describe_cluster_snapshots(SnapshotIdentifier=snapshot_id), *gone)
    still = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
    assert [c["ClusterCreateTime"] for c in still] == [created], (
        f"cluster {cluster_id} after the child-dropping update: {still!r}"
    )

    delete_stack(cfn, stack_id)
    gone = ("ClusterNotFound", f"Cluster {cluster_id} not found.")
    expect_error(lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
