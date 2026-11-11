"""deploy-cloudfront-realtimelogconfig-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudfront-realtimelogconfig-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront", "iam", "kinesis"]

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

_NOT_FOUND_CODE = "NoSuchRealtimeLogConfig"
_NOT_FOUND_MSG = "The specified real-time log configuration does not exist."
_POLICY_NAME = "sim2real-cfnrlc-kinesis-put"
_FIELDS = ["timestamp", "c-ip"]
_TRUST_CLOUDFRONT = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _put_policy(stream_arn):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                       "Resource": stream_arn}],
    }


def _template(stream_name, role_name, rlc_name, sampling_rate):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Stream": {"Type": "AWS::Kinesis::Stream",
                       "Properties": {"ShardCount": 1, "Name": stream_name}},
            "Role": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST_CLOUDFRONT,
                "Policies": [{"PolicyName": _POLICY_NAME,
                              "PolicyDocument": _put_policy({"Fn::GetAtt": ["Stream", "Arn"]})}],
            }},
            "RLC": {"Type": "AWS::CloudFront::RealtimeLogConfig", "Properties": {
                "Name": rlc_name,
                "EndPoints": [{"StreamType": "Kinesis", "KinesisStreamConfig": {
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "StreamArn": {"Fn::GetAtt": ["Stream", "Arn"]},
                }}],
                "Fields": _FIELDS,
                "SamplingRate": sampling_rate,
            }},
        },
        "Outputs": {
            "RLCRef": {"Value": {"Ref": "RLC"}},
            "RLCArn": {"Value": {"Fn::GetAtt": ["RLC", "Arn"]}},
            "StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


def _listed_configs(cfront):
    """Every ListRealtimeLogConfigs item; the op has no botocore paginator, so follow NextMarker."""
    listed, marker = [], ""
    while True:
        page = (cfront.list_realtime_log_configs(Marker=marker) if marker
                else cfront.list_realtime_log_configs())["RealtimeLogConfigs"]
        listed.extend(page.get("Items", []))
        marker = page.get("NextMarker")
        if not marker:
            return listed


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RealtimeLogConfig, its Kinesis stream and IAM role read back through their
    owning services with every templated property and tag; deleting the stack removes the config.
    """
    cfront = ctx.client("cloudfront")
    cf = ctx.client("cloudformation")
    iam = ctx.client("iam")
    kinesis = ctx.client("kinesis")
    stack = ctx.unique_name("sim2real-cfnrlc-stack-")
    stream_name = ctx.unique_name("sim2real-cfnrlc-stream-")
    role_name = ctx.unique_name("sim2real-cfnrlc-role-")
    rlc_name = ctx.unique_name("sim2real-cfnrlc-")

    stack_id = create_stack(ctx, cf, stack, _template(stream_name, role_name, rlc_name, 100),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    stream_arn = f"arn:{partition}:kinesis:{ctx.region}:{ctx.account}:stream/{stream_name}"
    role_arn = f"arn:{partition}:iam::{ctx.account}:role/{role_name}"
    rlc_arn = f"arn:{partition}:cloudfront::{ctx.account}:realtime-log-config/{rlc_name}"

    # The role by its templated name: ARN, trust policy, the one inline policy and the stack tag.
    role = iam.get_role(RoleName=role_name)["Role"]
    assert (out["RoleArn"], role["Arn"]) == (role_arn, role_arn), (
        f"GetAtt Role.Arn {out['RoleArn']!r}, IAM Arn {role['Arn']!r}, expected {role_arn!r}"
    )
    assert role["AssumeRolePolicyDocument"] == _TRUST_CLOUDFRONT, (
        f"role trust policy {role['AssumeRolePolicyDocument']!r}"
    )
    names = paginate(iam, "list_role_policies", "PolicyNames", RoleName=role_name)
    assert names == [_POLICY_NAME], f"inline policies {names!r}"
    doc = iam.get_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME)["PolicyDocument"]
    assert doc == _put_policy(stream_arn), f"inline policy {doc!r}"
    role_tags = paginate(iam, "list_role_tags", "Tags", RoleName=role_name)
    assert role_tags == [{"Key": "sim2real", "Value": stack}], f"role tags {role_tags!r}"

    # The stream by its templated name: ARN, one open shard and the propagated stack tag.
    stream = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    got = (stream["StreamARN"], out["StreamArn"], stream["StreamStatus"], stream["OpenShardCount"])
    assert got == (stream_arn, stream_arn, "ACTIVE", 1), f"stream reads {got!r}"
    # The stream also carries CloudFormation's aws:cloudformation:* system tags; drop aws: keys.
    page = kinesis.list_tags_for_stream(StreamName=stream_name)
    stream_tags = [t for t in page["Tags"] if not t["Key"].startswith("aws:")]
    assert (stream_tags, page["HasMoreTags"]) == ([{"Key": "sim2real", "Value": stack}], False), (
        f"stream tags {page!r}"
    )

    # Ref and GetAtt against an independent ListRealtimeLogConfigs entry and the documented ARN.
    matches = [c for c in _listed_configs(cfront) if c["Name"] == rlc_name]
    assert [c["ARN"] for c in matches] == [rlc_arn], f"ListRealtimeLogConfigs found {matches!r}"
    assert (out["RLCRef"], out["RLCArn"]) == (rlc_arn, rlc_arn), (
        f"Ref {out['RLCRef']!r}, GetAtt Arn {out['RLCArn']!r}, expected {rlc_arn!r}"
    )
    rlc = cfront.get_realtime_log_config(Name=rlc_name)["RealtimeLogConfig"]
    want = {
        "ARN": rlc_arn, "Name": rlc_name, "SamplingRate": 100, "Fields": _FIELDS,
        "EndPoints": [{"StreamType": "Kinesis", "KinesisStreamConfig": {
            "RoleARN": role_arn, "StreamARN": stream_arn}}],
    }
    assert rlc == want, f"GetRealtimeLogConfig read {rlc!r}, expected {want!r}"
    assert matches == [want], f"listed entry {matches!r}, expected {want!r}"

    delete_stack(cf, stack_id)
    refused = (_NOT_FOUND_CODE, _NOT_FOUND_MSG)
    expect_error(lambda: cfront.get_realtime_log_config(Name=rlc_name), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
