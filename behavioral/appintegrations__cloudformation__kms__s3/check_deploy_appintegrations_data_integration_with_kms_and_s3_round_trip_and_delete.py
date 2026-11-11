"""deploy-appintegrations-data-integration-with-kms-and-s3-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appintegrations-data-integration-with-kms-and-s3-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["appintegrations", "cloudformation", "kms", "s3"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_KEY_DESCRIPTION = "sim2real appintegrations data integration key"


def _key_policy():
    """Account-root administration only: the key is usable through IAM in this account alone."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EnableRoot", "Effect": "Allow",
            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
            "Action": "kms:*", "Resource": "*",
        }],
    }


def _template(bucket_name, di_name, source_uri):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DiKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": _KEY_DESCRIPTION,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": _key_policy(),
                    "Tags": [{"Key": "sim2real-key", "Value": di_name}],
                },
            },
            "DiBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name,
                               "Tags": [{"Key": "sim2real-bucket", "Value": bucket_name}]},
            },
            "Di": {
                "Type": "AWS::AppIntegrations::DataIntegration",
                "Properties": {
                    "Name": di_name,
                    "KmsKey": {"Fn::GetAtt": ["DiKey", "Arn"]},
                    "SourceURI": source_uri,
                    "Tags": [{"Key": "sim2real-di", "Value": di_name}],
                },
                "DependsOn": ["DiBucket", "DiKey"],
            },
        },
        "Outputs": {
            "DiId": {"Value": {"Ref": "Di"}},
            "DiArn": {"Value": {"Fn::GetAtt": ["Di", "DataIntegrationArn"]}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["DiKey", "Arn"]}},
        },
    })


def _listed(appi, name):
    return [d for d in paginate(appi, "list_data_integrations", "DataIntegrations")
            if d["Name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AppIntegrations DataIntegration on its own S3 bucket and KMS key reads back.

    Ref and GetAtt match an independent listing, every property and tag reads back through the
    owning services, and deleting the stack removes it.
    """
    cfn = ctx.client("cloudformation")
    appi = ctx.client("appintegrations")
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    stack = ctx.unique_name("sim2real-appint-di-stack-")
    bucket_name = ctx.unique_name("sim2real-appint-di-bucket-")
    di_name = ctx.unique_name("sim2real-appint-di-")

    stack_id = create_stack(ctx, cfn, stack, _template(bucket_name, di_name,
                                                       {"Fn::Sub": "S3://${DiBucket}"}))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    di_arn = (f"arn:{partition}:app-integrations:{ctx.region}:{ctx.account}:"
              f"data-integration/{out['DiId']}")

    # Ref and GetAtt against an independent listing by the templated name.
    listed = [(d["Arn"], d["SourceURI"]) for d in _listed(appi, di_name)]
    assert listed == [(di_arn, f"S3://{bucket_name}")], f"ListDataIntegrations found {listed!r}"
    assert out["DiArn"] == di_arn, f"GetAtt DataIntegrationArn {out['DiArn']!r} != {di_arn!r}"

    # The key and the bucket through their own services, by the template's names and tags.
    key = kms.describe_key(KeyId=out["KeyArn"])["KeyMetadata"]
    got = (key["Arn"], key["Description"], key["KeyState"])
    assert got == (out["KeyArn"], _KEY_DESCRIPTION, "Enabled"), f"DescribeKey reads {got!r}"
    policy = json.loads(kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")["Policy"])
    want = {"Version": "2012-10-17", "Statement": [{
        "Sid": "EnableRoot", "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{ctx.account}:root"},
        "Action": "kms:*", "Resource": "*"}]}
    assert policy == want, f"key policy {policy!r}, expected {want!r}"
    key_tags = {t["TagKey"]: t["TagValue"]
                for t in paginate(kms, "list_resource_tags", "Tags", KeyId=key["KeyId"])
                if not t["TagKey"].startswith("aws:")}
    assert key_tags == {"sim2real": stack, "sim2real-key": di_name}, f"key tags {key_tags!r}"
    bucket_tags = {t["Key"]: t["Value"]
                   for t in s3.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
                   if not t["Key"].startswith("aws:")}
    assert bucket_tags == {"sim2real": stack, "sim2real-bucket": bucket_name}, (
        f"bucket tags {bucket_tags!r}"
    )

    di = appi.get_data_integration(Identifier=out["DiId"])
    got = (di["Id"], di["Arn"], di["Name"], di["KmsKey"], di["SourceURI"],
           {k: v for k, v in di.get("Tags", {}).items() if not k.startswith("aws:")})
    want = (out["DiId"], di_arn, di_name, key["Arn"], f"S3://{bucket_name}",
            {"sim2real": stack, "sim2real-di": di_name})
    assert got == want, f"GetDataIntegration reads {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException",
            f"Could not find DataIntegration with identifier: {out['DiId']}.")
    until_raises(lambda: appi.get_data_integration(Identifier=out["DiId"]))
    expect_error(lambda: appi.get_data_integration(Identifier=out["DiId"]), *gone)
    assert _listed(appi, di_name) == [], "the deleted DataIntegration is still listed"
    state = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"the stack-deleted key reads KeyState {state!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
