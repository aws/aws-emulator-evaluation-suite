"""deploy-apigateway-vpclink-invalid-target-arn-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-vpclink-invalid-target-arn-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation", "ec2", "elbv2"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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

_TAG_KEY = "sim2real-vpclink"


def _template(vpc_link_name: str, cidr_prefix: str) -> str:
    """A VPC, a subnet, an internal NLB and a VpcLink targeting it."""
    t = [{"Key": _TAG_KEY, "Value": vpc_link_name}]
    return json.dumps({
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": f"{cidr_prefix}.0.0/16", "Tags": t}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": f"{cidr_prefix}.1.0/24",
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "Tags": t}},
            "Nlb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
                "Type": "network", "Scheme": "internal", "Subnets": [{"Ref": "Subnet"}],
                "Tags": t}},
            "VpcLink": {"Type": "AWS::ApiGateway::VpcLink", "Properties": {
                "Name": vpc_link_name, "TargetArns": [{"Ref": "Nlb"}], "Tags": t}},
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "NlbArn": {"Value": {"Ref": "Nlb"}},
            "VpcLinkId": {"Value": {"Ref": "VpcLink"}},
            "VpcLinkIdGetAtt": {"Value": {"Fn::GetAtt": ["VpcLink", "VpcLinkId"]}},
        },
    })


def _links_named(apigw, name: str) -> list:
    return [x for x in paginate(apigw, "get_vpc_links", "items") if x["name"] == name]


def _assert_link_and_nlb(apigw, elbv2, ec2, out: dict, name: str, cidr_prefix: str) -> None:
    """The link listed under its name matches the Ref and template; the NLB and subnet too."""
    listed = _links_named(apigw, name)
    assert [x["id"] for x in listed] == [out["VpcLinkId"]], (
        f"VPC links named {name!r}: {listed!r}, Ref {out['VpcLinkId']!r}"
    )
    link = listed[0]
    got = (link["targetArns"], link["status"],
           {k: v for k, v in link.get("tags", {}).items() if k == _TAG_KEY})
    want = ([out["NlbArn"]], "AVAILABLE", {_TAG_KEY: name})
    assert got == want, f"VPC link reads {got!r}, expected {want!r}"
    nlbs = paginate(elbv2, "describe_load_balancers", "LoadBalancers",
                    LoadBalancerArns=[out["NlbArn"]])
    got = [(n["Type"], n["Scheme"], n["VpcId"], n["State"]["Code"]) for n in nlbs]
    assert got == [("network", "internal", out["VpcId"], "active")], f"NLB reads {got!r}"
    subnets = ec2.describe_subnets(SubnetIds=[out["SubnetId"]])["Subnets"]
    got = [(s["VpcId"], s["CidrBlock"]) for s in subnets]
    assert got == [(out["VpcId"], f"{cidr_prefix}.1.0/24")], f"subnet reads {got!r}"


def _bad_template(vpc_link_name: str, bad_arn: str) -> str:
    """The same VpcLink with TargetArns naming an NLB that does not exist."""
    return json.dumps({
        "Resources": {
            "VpcLink": {"Type": "AWS::ApiGateway::VpcLink", "Properties": {
                "Name": vpc_link_name, "TargetArns": [bad_arn],
                "Tags": [{"Key": _TAG_KEY, "Value": vpc_link_name}]}},
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation VpcLink whose TargetArns names a missing NLB fails and rolls back.

    API Gateway fails to stabilize it and lists no link by its name, while the same VpcLink
    targeting a real internal NLB reaches AVAILABLE.
    """
    cfn = ctx.client("cloudformation")
    apigw = ctx.client("apigateway")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")
    good_name = ctx.unique_name("sim2real-behav-vpclinkgood-")
    bad_name = ctx.unique_name("sim2real-behav-vpclinkbad-")

    # Both stacks deploy at once; the control gives TargetArns a real NLB.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-vpclinkgoodstack-"),
                           _template(good_name, "10.94"))
    bad_arn = (
        f"arn:{good_id.split(':')[1]}:elasticloadbalancing:{ctx.region}:{ctx.account}:"
        f"loadbalancer/net/{ctx.unique_name('sim2real-missingnlb-')[:32]}/0123456789abcdef"
    )
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-vpclinkbadstack-"),
                          _bad_template(bad_name, bad_arn))

    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    _assert_link_and_nlb(apigw, elbv2, ec2, stack_outputs(cfn, good_id), good_name, "10.94")

    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = [e for e in stack_events(cfn, bad_id)
            if e["LogicalResourceId"] == "VpcLink" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"VpcLink CREATE_FAILED rows {rows!r}"
    link_id = rows[0]["PhysicalResourceId"]
    got = handler_reason(rows[0].get("ResourceStatusReason"), ctx.account)
    want = (f"Failed to stabilize Vpc Link with id {link_id} Status Message NLB ARN not found.",
            "GeneralServiceException")
    assert got == want, f"VpcLink reason {got!r}, expected {want!r}"

    # Rollback absence through API Gateway, by name and by the id it had, before the delete.
    assert _links_named(apigw, bad_name) == [], f"a VPC link named {bad_name!r} is listed"
    refused = ("NotFoundException", "Invalid Vpc Link identifier specified")
    expect_error(lambda: apigw.get_vpc_link(vpcLinkId=link_id), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
