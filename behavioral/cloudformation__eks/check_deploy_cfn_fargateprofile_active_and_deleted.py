"""deploy-cfn-fargateprofile-active-and-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-fargateprofile-active-and-deleted"
GROUP = "deploy"
SERVICES = ["cloudformation", "eks"]

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

_NAMESPACE = "sim2real-fargate-ns"


def _role(service, policy):
    return {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]},
        "ManagedPolicyArns": [{"Fn::Sub": f"arn:${{AWS::Partition}}:iam::aws:policy/{policy}"}],
    }}


_PROFILE_NOT_FOUND = ("ResourceNotFoundException", "The requested resource does not exist.")


def _cluster_not_found(cluster_name):
    return ("ResourceNotFoundException", f"No cluster found for name: {cluster_name}.")


def _template(cluster_name, profile_name, subnets, private_subnets, with_profile=True):
    resources = {
        "ClusterRole": _role("eks.amazonaws.com", "AmazonEKSClusterPolicy"),
        "FargateRole": _role("eks-fargate-pods.amazonaws.com",
                             "AmazonEKSFargatePodExecutionRolePolicy"),
        # Private API endpoint only: nothing the check deploys is reachable from the internet.
        "EksCluster": {"Type": "AWS::EKS::Cluster", "Properties": {
            "Name": cluster_name,
            "RoleArn": {"Fn::GetAtt": ["ClusterRole", "Arn"]},
            "ResourcesVpcConfig": {"SubnetIds": subnets, "EndpointPublicAccess": False,
                                   "EndpointPrivateAccess": True},
        }},
    }
    outputs = {
        "ClusterRefOut": {"Value": {"Ref": "EksCluster"}},
        "ClusterArnOut": {"Value": {"Fn::GetAtt": ["EksCluster", "Arn"]}},
        "ClusterEndpointOut": {"Value": {"Fn::GetAtt": ["EksCluster", "Endpoint"]}},
        "ClusterRoleArn": {"Value": {"Fn::GetAtt": ["ClusterRole", "Arn"]}},
        "FargateRoleArn": {"Value": {"Fn::GetAtt": ["FargateRole", "Arn"]}},
    }
    if with_profile:
        resources["FargateProfile"] = {"Type": "AWS::EKS::FargateProfile", "Properties": {
            "ClusterName": {"Ref": "EksCluster"},
            "FargateProfileName": profile_name,
            "PodExecutionRoleArn": {"Fn::GetAtt": ["FargateRole", "Arn"]},
            "Subnets": private_subnets,
            "Selectors": [{"Namespace": _NAMESPACE}],
            "Tags": [{"Key": "sim2real-fp", "Value": profile_name}],
        }}
        outputs["ProfileRefOut"] = {"Value": {"Ref": "FargateProfile"}}
        outputs["ProfileArnOut"] = {"Value": {"Fn::GetAtt": ["FargateProfile", "Arn"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(tag_map):
    return {k: v for k, v in (tag_map or {}).items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EKS Fargate profile reaches ACTIVE on its cluster and reads back as set.

    An update dropping the profile deletes it while the cluster stays ACTIVE, and the stack's
    delete removes the cluster.
    """
    cf = ctx.client("cloudformation")
    eks = ctx.client("eks")
    network = ctx.network(private=True)
    subnets, private_subnets = list(network.subnet_ids), list(network.private_subnet_ids)
    stack = ctx.unique_name("sim2real-eks-cfnfp-stack-")
    cluster_name = ctx.unique_name("sim2real-eks-cfnfp-")
    profile_name = ctx.unique_name("sim2real-eks-cfnfp-fp-")

    # An EKS cluster takes about ten minutes to create, so this check deploys one stack only.
    stack_id = create_stack(ctx, cf, stack,
                            _template(cluster_name, profile_name, subnets, private_subnets),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id, timeout_s=1200.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Cluster Ref against an independent, fully paged ListClusters.
    listed = [n for n in paginate(eks, "list_clusters", "clusters") if n == cluster_name]
    assert listed == [out["ClusterRefOut"]] == [cluster_name], (
        f"ListClusters {listed!r}, Ref {out['ClusterRefOut']!r}"
    )
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    vpc = cluster["resourcesVpcConfig"]
    got = (cluster["status"], cluster["arn"], cluster["endpoint"], cluster["roleArn"],
           sorted(vpc["subnetIds"]), vpc["endpointPublicAccess"], vpc["endpointPrivateAccess"],
           _own_tags(cluster.get("tags")))
    want = ("ACTIVE", out["ClusterArnOut"], out["ClusterEndpointOut"], out["ClusterRoleArn"],
            sorted(subnets), False, True, {"sim2real": stack})
    assert got == want, f"DescribeCluster {got!r}, expected {want!r}"

    # Profile Ref (cluster|name) against the cluster's own ListFargateProfiles.
    profiles = paginate(eks, "list_fargate_profiles", "fargateProfileNames",
                        clusterName=cluster_name)
    assert profiles == [profile_name], f"ListFargateProfiles {profiles!r}"
    assert out["ProfileRefOut"] == f"{cluster_name}|{profile_name}", (
        f"Ref {out['ProfileRefOut']!r}, expected {cluster_name}|{profile_name}"
    )
    fp = eks.describe_fargate_profile(clusterName=cluster_name,
                                      fargateProfileName=profile_name)["fargateProfile"]
    got_fp = (fp["status"], fp["fargateProfileArn"], fp["clusterName"], fp["podExecutionRoleArn"],
              sorted(fp["subnets"]), fp["selectors"], _own_tags(fp.get("tags")))
    want_fp = ("ACTIVE", out["ProfileArnOut"], cluster_name, out["FargateRoleArn"],
               # AWS returns the unset selector labels as {}.
               sorted(private_subnets), [{"namespace": _NAMESPACE, "labels": {}}],
               {"sim2real": stack, "sim2real-fp": profile_name})
    assert got_fp == want_fp, f"DescribeFargateProfile {got_fp!r}, expected {want_fp!r}"

    # The profile alone: an update dropping it deletes it while the cluster stays ACTIVE.
    cf.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"], TemplateBody=_template(
        cluster_name, profile_name, subnets, private_subnets, with_profile=False))
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"profile-removing update ended {status!r}"
    expect_error(
        lambda: eks.describe_fargate_profile(clusterName=cluster_name,
                                             fargateProfileName=profile_name),
        *_PROFILE_NOT_FOUND,
    )
    assert eks.describe_cluster(name=cluster_name)["cluster"]["status"] == "ACTIVE", (
        "the cluster did not stay ACTIVE after its Fargate profile was removed"
    )

    delete_stack(cf, stack_id)
    cluster_gone = _cluster_not_found(cluster_name)
    expect_error(lambda: eks.describe_cluster(name=cluster_name), *cluster_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
