"""deploy-glue-catalog-encryption-settings-singleton-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-glue-catalog-encryption-settings-singleton-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue"]

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


# ---- Check-specific: the template, then run(). ----

def _encryption_template(key_description: str, catalog_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": key_description,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "root",
                            "Effect": "Allow",
                            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                            "Action": "kms:*",
                            "Resource": "*",
                        }],
                    },
                },
            },
            "Settings": {
                "Type": "AWS::Glue::DataCatalogEncryptionSettings",
                "Properties": {
                    "CatalogId": catalog_id,
                    "DataCatalogEncryptionSettings": {
                        "EncryptionAtRest": {
                            "CatalogEncryptionMode": "SSE-KMS",
                            "SseAwsKmsKeyId": {"Ref": "Key"},
                        },
                    },
                },
            },
        },
        "Outputs": {
            "KeyId": {"Value": {"Ref": "Key"}},
            "SettingsRef": {"Value": {"Ref": "Settings"}},
        },
    })


def _at_rest_mode(glue, catalog_id: str) -> str:
    settings = glue.get_data_catalog_encryption_settings(CatalogId=catalog_id)
    return settings["DataCatalogEncryptionSettings"]["EncryptionAtRest"]["CatalogEncryptionMode"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:glue-catalog-encryption")
def run(ctx) -> None:
    """CloudFormation deploys the account's Glue Data Catalog encryption settings, an
    account-wide singleton; it reads back through Glue's own GetDataCatalogEncryptionSettings
    with the template's KMS key, and deleting the stack reverts the catalog to unconfigured.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-glue-datacatalogencryptionsettings.html
    """
    glue = ctx.client("glue")
    cfn = ctx.client("cloudformation")

    prior_mode = _at_rest_mode(glue, ctx.account)
    assert prior_mode == "DISABLED", (
        f"precondition failed: the catalog encryption is already {prior_mode!r}, "
        f"expected 'DISABLED' before this check configures it"
    )

    enc_stack = ctx.unique_name("sim2real-gluecatalogenc-")
    enc_id = create_stack(ctx, cfn, enc_stack, _encryption_template(CHECK, ctx.account))
    status = wait_stack(cfn, enc_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {enc_stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, enc_id))!r}"
    )
    outputs = stack_outputs(cfn, enc_id)
    key_id = outputs["KeyId"]
    # The primary identifier is the template's CatalogId.
    assert outputs["SettingsRef"] == ctx.account, (
        f"Ref of DataCatalogEncryptionSettings must be the CatalogId, got {outputs['SettingsRef']!r}"
    )

    settings = glue.get_data_catalog_encryption_settings(CatalogId=ctx.account)
    at_rest = settings["DataCatalogEncryptionSettings"]["EncryptionAtRest"]
    assert at_rest["CatalogEncryptionMode"] == "SSE-KMS", (
        f"expected CatalogEncryptionMode 'SSE-KMS', Glue reports {at_rest['CatalogEncryptionMode']!r}"
    )
    assert at_rest["SseAwsKmsKeyId"] == key_id, (
        f"expected SseAwsKmsKeyId {key_id!r}, Glue reports {at_rest['SseAwsKmsKeyId']!r}"
    )

    delete_stack(cfn, enc_id)
    # The singleton read is eventually consistent: poll, bounded, to the reverted mode.
    deadline = time.monotonic() + 60.0
    reverted_mode = _at_rest_mode(glue, ctx.account)
    while reverted_mode != "DISABLED" and time.monotonic() < deadline:
        time.sleep(2.0)
        reverted_mode = _at_rest_mode(glue, ctx.account)
    assert reverted_mode == "DISABLED", (
        f"expected CatalogEncryptionMode 'DISABLED' after stack delete, Glue reports "
        f"{reverted_mode!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
