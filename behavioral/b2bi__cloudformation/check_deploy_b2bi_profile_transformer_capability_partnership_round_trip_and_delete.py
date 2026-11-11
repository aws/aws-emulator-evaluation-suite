"""deploy-b2bi-profile-transformer-capability-partnership-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-b2bi-profile-transformer-capability-partnership-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["b2bi", "cloudformation"]

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

_X12 = {"TransactionSet": "X12_850", "Version": "VERSION_4010"}
_PHONE = "+15555550100"


def _bucket_resources(bucket):
    """The capability's S3 bucket and a policy letting b2bi in this account read and write it."""
    return {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
        "BucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "Bucket"},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AllowB2BIAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "b2bi.amazonaws.com"},
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                   "s3:ListBucket"],
                        "Resource": [{"Fn::GetAtt": ["Bucket", "Arn"]},
                                     {"Fn::Sub": "${Bucket.Arn}/*"}],
                        "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}},
                    }],
                },
            },
        },
    }


def _transformer(name):
    return {
        "Type": "AWS::B2BI::Transformer",
        "Properties": {
            "Name": name,
            "Status": "active",
            "InputConversion": {"FromFormat": "X12", "FormatOptions": {"X12": _X12}},
            "Mapping": {"TemplateLanguage": "JSONATA", "Template": "$"},
        },
    }


def _capability(name, bucket, transformer_id):
    return {
        "Type": "AWS::B2BI::Capability",
        "DependsOn": "BucketPolicy",
        "Properties": {
            "Name": name,
            "Type": "edi",
            "Configuration": {
                "Edi": {
                    "Type": {"X12Details": _X12},
                    "InputLocation": {"BucketName": bucket, "Key": "in/"},
                    "OutputLocation": {"BucketName": bucket, "Key": "out/"},
                    "TransformerId": transformer_id,
                    "CapabilityDirection": "INBOUND",
                },
            },
        },
    }


def _reasons(events):
    """``(logical id, status, reason)`` of every event row with a reason, oldest first."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e["ResourceStatusReason"])
            for e in events if e.get("ResourceStatusReason")]


def _empty_bucket(s3, bucket):
    """Delete every object in the stack's bucket (b2bi writes into it) so the stack can delete it.

    A bucket that never existed (the stack failed before creating it) is the exact NoSuchBucket.
    """
    try:
        keys = [{"Key": o["Key"]}
                for o in paginate(s3, "list_objects_v2", "Contents", Bucket=bucket)]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    for i in range(0, len(keys), 1000):
        errors = s3.delete_objects(Bucket=bucket,
                                   Delete={"Objects": keys[i:i + 1000]}).get("Errors")
        assert not errors, f"emptying {bucket}: {errors!r}"


def _named(b2bi, op, key, name, **kw):
    return [x for x in paginate(b2bi, op, key, **kw) if x["name"] == name]


def _template(bucket, names, email, with_children=True):
    resources = {
        **_bucket_resources(bucket),
        "Profile": {
            "Type": "AWS::B2BI::Profile",
            "Properties": {"Name": names["profile"], "BusinessName": names["business"],
                           "Phone": _PHONE, "Logging": "DISABLED"},
        },
        "Transformer": _transformer(names["transformer"]),
    }
    outputs = {
        "ProfileId": {"Value": {"Ref": "Profile"}},
        "ProfileArn": {"Value": {"Fn::GetAtt": ["Profile", "ProfileArn"]}},
        "TransformerId": {"Value": {"Ref": "Transformer"}},
        "TransformerArn": {"Value": {"Fn::GetAtt": ["Transformer", "TransformerArn"]}},
    }
    if with_children:
        resources["Capability"] = _capability(names["capability"], bucket, {"Ref": "Transformer"})
        resources["Partnership"] = {
            "Type": "AWS::B2BI::Partnership",
            "Properties": {
                "Name": names["partnership"],
                "Email": email,
                "ProfileId": {"Ref": "Profile"},
                "Capabilities": [{"Ref": "Capability"}],
            },
        }
        outputs.update({
            "CapabilityId": {"Value": {"Ref": "Capability"}},
            "CapabilityArn": {"Value": {"Fn::GetAtt": ["Capability", "CapabilityArn"]}},
            "PartnershipId": {"Value": {"Ref": "Partnership"}},
            "PartnershipArn": {"Value": {"Fn::GetAtt": ["Partnership", "PartnershipArn"]}},
            "PartnershipTradingPartnerId": {
                "Value": {"Fn::GetAtt": ["Partnership", "TradingPartnerId"]}
            },
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation B2BI Profile, Transformer, Capability and Partnership read back from b2bi.

    Refs match independent listings; an update dropping the Capability and Partnership removes
    both while their parents answer, and the stack delete removes the Profile and Transformer.
    """
    cfn = ctx.client("cloudformation")
    b2bi = ctx.client("b2bi")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-b2bicfn-")
    names = {part: ctx.unique_name(f"sim2real-behav-b2bi-{part}-")
             for part in ("profile", "business", "transformer", "capability", "partnership")}
    email = f"{ctx.unique_name('sim2real-b2bi-ptn-')}@example.com"

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-b2bi-"),
                            _template(bucket, names, email))
    # Registered after the stack's delete, so it runs first: the bucket must be empty to delete.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    status = wait_stack(cfn, stack_id)
    # Every event reason, so a rollback names its cause.
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {_reasons(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Every Ref against an independent listing by the templated name.
    profiles = _named(b2bi, "list_profiles", "profiles", names["profile"])
    assert [p["profileId"] for p in profiles] == [out["ProfileId"]], f"ListProfiles: {profiles!r}"
    profile_id = profiles[0]["profileId"]
    transformers = _named(b2bi, "list_transformers", "transformers", names["transformer"])
    assert [t["transformerId"] for t in transformers] == [out["TransformerId"]], (
        f"ListTransformers: {transformers!r}"
    )
    transformer_id = transformers[0]["transformerId"]
    capabilities = _named(b2bi, "list_capabilities", "capabilities", names["capability"])
    assert [c["capabilityId"] for c in capabilities] == [out["CapabilityId"]], (
        f"ListCapabilities: {capabilities!r}"
    )
    capability_id = capabilities[0]["capabilityId"]
    partnerships = _named(b2bi, "list_partnerships", "partnerships", names["partnership"],
                          profileId=profile_id)
    got = [(p["partnershipId"], p["capabilities"], p["tradingPartnerId"]) for p in partnerships]
    want = [(out["PartnershipId"], [capability_id], out["PartnershipTradingPartnerId"])]
    assert got == want, f"ListPartnerships: {got!r}, expected {want!r}"
    partnership_id = partnerships[0]["partnershipId"]

    # Every templated property and GetAtt through b2bi.
    profile = b2bi.get_profile(profileId=profile_id)
    got = (profile["profileArn"], profile["name"], profile["businessName"], profile["phone"],
           profile["logging"])
    want = (out["ProfileArn"], names["profile"], names["business"], _PHONE, "DISABLED")
    assert got == want, f"GetProfile reads {got!r}, expected {want!r}"
    transformer = b2bi.get_transformer(transformerId=transformer_id)
    conversion, mapping = transformer["inputConversion"], transformer["mapping"]
    got = (transformer["transformerArn"], transformer["name"], transformer["status"],
           {k: conversion.get(k) for k in ("fromFormat", "formatOptions")},
           {k: mapping.get(k) for k in ("templateLanguage", "template")})
    want = (out["TransformerArn"], names["transformer"], "active",
            {"fromFormat": "X12", "formatOptions": {"x12": {"transactionSet": "X12_850",
                                                            "version": "VERSION_4010"}}},
            {"templateLanguage": "JSONATA", "template": "$"})
    assert got == want, f"GetTransformer reads {got!r}, expected {want!r}"
    capability = b2bi.get_capability(capabilityId=capability_id)
    edi = capability["configuration"]["edi"]
    got = (capability["capabilityArn"], capability["name"], capability["type"],
           {k: edi.get(k) for k in ("type", "inputLocation", "outputLocation", "transformerId",
                                    "capabilityDirection")})
    want = (out["CapabilityArn"], names["capability"], "edi", {
        "type": {"x12Details": {"transactionSet": "X12_850", "version": "VERSION_4010"}},
        "inputLocation": {"bucketName": bucket, "key": "in/"},
        "outputLocation": {"bucketName": bucket, "key": "out/"},
        "transformerId": transformer_id,
        "capabilityDirection": "INBOUND",
    })
    assert got == want, f"GetCapability reads {got!r}, expected {want!r}"
    partnership = b2bi.get_partnership(partnershipId=partnership_id)
    got = (partnership["partnershipArn"], partnership["name"], partnership["email"],
           partnership["profileId"], partnership["capabilities"])
    want = (out["PartnershipArn"], names["partnership"], email, profile_id, [capability_id])
    assert got == want, f"GetPartnership reads {got!r}, expected {want!r}"

    # Children before parents: the update drops the Capability and the Partnership while the
    # same Profile and Transformer (createdAt unchanged) still answer.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(bucket, names, email, with_children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    gone = [
        (lambda: b2bi.get_partnership(partnershipId=partnership_id),
         ("ResourceNotFoundException",
          f"Partnership with partnershipId {partnership_id} not found.")),
        (lambda: b2bi.get_capability(capabilityId=capability_id),
         ("ResourceNotFoundException", f"Capability ID {capability_id} not found.")),
    ]
    for read, refused in gone:
        until_raises(read)
        expect_error(read, *refused)
    after = (b2bi.get_profile(profileId=profile_id)["createdAt"],
             b2bi.get_transformer(transformerId=transformer_id)["createdAt"])
    assert after == (profile["createdAt"], transformer["createdAt"]), (
        f"the parents changed across the update: {after!r}"
    )

    _empty_bucket(s3, bucket)
    delete_stack(cfn, stack_id)
    gone = [
        (lambda: b2bi.get_transformer(transformerId=transformer_id),
         ("ResourceNotFoundException", f"Transformer not found with ID {transformer_id}")),
        (lambda: b2bi.get_profile(profileId=profile_id),
         ("ResourceNotFoundException", f"Profile ID {profile_id} not found.")),
    ]
    for read, refused in gone:
        until_raises(read)
        expect_error(read, *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
