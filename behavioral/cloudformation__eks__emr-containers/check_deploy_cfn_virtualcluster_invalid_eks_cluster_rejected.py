"""deploy-cfn-virtualcluster-invalid-eks-cluster-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-virtualcluster-invalid-eks-cluster-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "eks", "emr-containers"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


_CLUSTER_STACK_TIMEOUT_S = 1200.0
_ROLE_PROPAGATION_DEADLINE_S = 120.0
# The namespace the CFN handler requires to exist on the cluster; every cluster has "default".
_NAMESPACE = "default"
# EKS refusing a role IAM has not propagated yet: the one cluster-stack failure that is retried.
_ROLE_NOT_PROPAGATED = re.compile(
    r"^Role with arn: arn:[^ ]+, could not be assumed because it does not exist or the trusted "
    r"entity is not correct \(Service: [^)]+\)$"
)
_SERVICE_FIELD = re.compile(r"\(Service: [^;]+;")


def _cluster_stack_template(cluster_name: str) -> str:
    """A private VPC (no internet route) and an EKS cluster with a private-only endpoint."""
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(2)]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": "10.73.0.0/16", "EnableDnsSupport": True, "EnableDnsHostnames": True}},
            "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.73.0.0/24", "AvailabilityZone": az[0]}},
            "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.73.1.0/24", "AvailabilityZone": az[1]}},
            "ClusterRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]},
                "ManagedPolicyArns": [
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonEKSClusterPolicy"}],
            }},
            "Cluster": {"Type": "AWS::EKS::Cluster", "Properties": {
                "Name": cluster_name,
                "RoleArn": {"Fn::GetAtt": ["ClusterRole", "Arn"]},
                "ResourcesVpcConfig": {
                    "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                    "EndpointPublicAccess": False, "EndpointPrivateAccess": True,
                },
                "AccessConfig": {"AuthenticationMode": "API_AND_CONFIG_MAP",
                                 "BootstrapClusterCreatorAdminPermissions": True},
            }},
        },
    })


def _virtualcluster_template(name: str, cluster_id: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"VC": {"Type": "AWS::EMRContainers::VirtualCluster", "Properties": {
            "Name": name,
            "ContainerProvider": {"Type": "EKS", "Id": cluster_id,
                                  "Info": {"EksInfo": {"Namespace": _NAMESPACE}}},
            "Tags": [{"Key": "sim2real-res", "Value": tag_value}],
        }}},
        "Outputs": {"VcRef": {"Value": {"Ref": "VC"}},
                    "VcArn": {"Value": {"Fn::GetAtt": ["VC", "Arn"]}}},
    })


def _virtual_clusters(emrc, provider_id: str) -> list[dict]:
    """Every virtual cluster (all pages) EMR on EKS lists under the EKS ``provider_id``."""
    return paginate(emrc, "list_virtual_clusters", "virtualClusters",
                    containerProviderId=provider_id, containerProviderType="EKS")


def _deploy_cluster(ctx, cfn) -> str:
    """A check-owned EKS cluster; only EKS's role-not-yet-propagated refusal is retried."""
    cluster_name = ctx.unique_name("sim2real-vc-eks-")
    deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S
    while True:
        stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-vc-clstack-"),
                                _cluster_stack_template(cluster_name),
                                Capabilities=["CAPABILITY_IAM"])
        status = wait_stack(cfn, stack_id, timeout_s=_CLUSTER_STACK_TIMEOUT_S)
        if status == "CREATE_COMPLETE":
            return cluster_name
        message, _ = handler_reason(failed_reason(stack_events(cfn, stack_id), "Cluster"),
                                    ctx.account)
        delete_stack(cfn, stack_id)
        assert _ROLE_NOT_PROPAGATED.match(message) and time.monotonic() < deadline, (
            f"cluster stack ended {status!r}: {message!r}"
        )
        # fixed-wait: paces retries of a whole stack re-create, not a poll of a cheap read
        time.sleep(5.0)


def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


def _cluster_access(eks, cluster_name):
    """Every EKS access entry of the cluster with its associated policies and scopes (diagnostic).

    EMR on EKS creates its own access entry for the namespace when a virtual cluster is created on
    an API_AND_CONFIG_MAP cluster; a failed control names what the cluster then held.
    """
    return {arn: [(p["policyArn"], p["accessScope"])
                  for p in paginate(eks, "list_associated_access_policies",
                                    "associatedAccessPolicies", clusterName=cluster_name,
                                    principalArn=arn)]
            for arn in paginate(eks, "list_access_entries", "accessEntries",
                                clusterName=cluster_name)}


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EMR on EKS virtual cluster naming a nonexistent EKS cluster is refused.

    The handler relays EMR on EKS's exact reason and nothing lists under that provider id, while
    the same template naming a real cluster deploys, reads back and tombstones TERMINATED.
    """
    cfn = ctx.client("cloudformation")
    eks = ctx.client("eks")
    emrc = ctx.client("emr-containers")

    cluster_name = _deploy_cluster(ctx, cfn)
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    got = (cluster["status"], cluster["resourcesVpcConfig"]["endpointPublicAccess"])
    assert got == ("ACTIVE", False), f"EKS cluster reads {got!r}"

    # The negative: only ContainerProvider.Id differs, naming a cluster that does not exist.
    missing_id = f"{cluster_name}-missing"
    bad_name = ctx.unique_name("sim2real-vc-bad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-vcbad-stack-"),
                          _virtualcluster_template(bad_name, missing_id, bad_name))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    message, code = handler_reason(failed_reason(stack_events(cfn, bad_id), "VC"), ctx.account,
                                   bad_name)
    got = (_SERVICE_FIELD.sub("(Service: <service>;", message), code)
    want = (f"Cluster {missing_id} not found (Service: <service>; Status Code: 400; "
            "Error Code: ValidationException; Request ID: <id>; Proxy: null)", "InvalidRequest")
    assert got == want, f"handler reason {got!r}, expected {want!r}"
    # Absence under the provider id the rejected template named, before this check's delete.
    names = [vc["name"] for vc in _virtual_clusters(emrc, missing_id)]
    assert bad_name not in names, f"{bad_name!r} lists under {missing_id!r}: {names!r}"
    delete_stack(cfn, bad_id)

    # Positive control: the same template naming the real cluster.
    good_name = ctx.unique_name("sim2real-vc-good-")
    good_stack = ctx.unique_name("sim2real-vcgood-stack-")
    good_id = create_stack(ctx, cfn, good_stack,
                           _virtualcluster_template(good_name, cluster_name, good_name))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {_reasons(stack_events(cfn, good_id))!r}; "
        f"cluster access entries {_cluster_access(eks, cluster_name)!r}"
    )
    out = stack_outputs(cfn, good_id)
    listed = [vc["id"] for vc in _virtual_clusters(emrc, cluster_name)
              if vc["name"] == good_name and vc["state"] == "RUNNING"]
    assert listed == [out["VcRef"]], f"virtual clusters named {good_name!r}: {listed!r}"
    vc = emrc.describe_virtual_cluster(id=out["VcRef"])["virtualCluster"]
    provider = vc["containerProvider"]
    got = (vc["arn"], vc["name"], vc["state"], provider["type"], provider["id"],
           provider["info"]["eksInfo"]["namespace"])
    want = (out["VcArn"], good_name, "RUNNING", "EKS", cluster_name, _NAMESPACE)
    assert got == want, f"virtual cluster reads {got!r}, expected {want!r}"
    vc_tags = {k: v for k, v in emrc.list_tags_for_resource(resourceArn=vc["arn"])["tags"].items()
               if not k.startswith("aws:")}
    assert vc_tags == {"sim2real": good_stack, "sim2real-res": good_name}, f"tags {vc_tags!r}"

    delete_stack(cfn, good_id)
    deadline = time.monotonic() + 180
    while True:  # deletion is asynchronous; poll to the terminal tombstone state
        state = emrc.describe_virtual_cluster(id=out["VcRef"])["virtualCluster"]["state"]
        if state in ("TERMINATED", "ARRESTED") or time.monotonic() > deadline:
            break
        time.sleep(5)
    assert state == "TERMINATED", f"virtual cluster ended {state!r}, expected TERMINATED"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
