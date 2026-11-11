"""deploy-kms-alias-cfn-invalid-target-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kms-alias-cfn-invalid-target-rejected"
GROUP = "deploy"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A stack whose AWS::KMS::Alias targets a non-existent key rolls back with a not-found Alias
    failure and leaves no alias; a valid key + alias stack deploys, and the alias resolves to the
    key and round-trips Encrypt/Decrypt."""
    bogus_key_id = "00000000-0000-0000-0000-000000000000"
    bad_alias_name = ctx.unique_name("alias/sim2real-behav-bad-")
    bad_stack_name = ctx.unique_name("sim2real-behav-kmsalias-bad-")
    bad_template = json.dumps(
        {
            "Resources": {
                "Alias": {
                    "Type": "AWS::KMS::Alias",
                    "Properties": {
                        "AliasName": bad_alias_name,
                        "TargetKeyId": bogus_key_id,
                    },
                }
            }
        }
    )
    _deploy_stack(ctx, bad_stack_name, bad_template)
    status = _wait_for_stack_status(ctx, bad_stack_name)
    assert status == "ROLLBACK_COMPLETE", f"expected rollback for invalid target key, got {status}"

    events = _stack_events(ctx, bad_stack_name)
    alias_failures = [
        e for e in events if e.get("LogicalResourceId") == "Alias" and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert alias_failures, f"expected a CREATE_FAILED event for the Alias resource, got {events}"
    reason = alias_failures[0].get("ResourceStatusReason", "")
    reason_lower = reason.lower()
    assert any(
        marker in reason_lower
        for marker in ("notfoundexception", "not found", "does not exist", "invalid keyid", "invalid arn")
    ), alias_failures[0]

    kms = ctx.client("kms")
    all_aliases = kms.list_aliases()["Aliases"]
    assert not any(
        a["AliasName"] == bad_alias_name for a in all_aliases
    ), f"expected no alias named {bad_alias_name} after rollback, but found one in {all_aliases}"

    # Positive control: a valid key + alias stack deploys and resolves cleanly.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    good_stack_name = ctx.unique_name("sim2real-behav-kmsalias-good-")
    good_alias_name = ctx.unique_name("alias/sim2real-behav-good-")
    good_template = json.dumps(
        {
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real behavioral control key",
                        "KeyPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "EnableRootPermissions",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                    "Action": "kms:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                },
                "Alias": {
                    "Type": "AWS::KMS::Alias",
                    "Properties": {
                        "AliasName": good_alias_name,
                        "TargetKeyId": {"Ref": "Key"},
                    },
                },
            },
            "Outputs": {"KeyId": {"Value": {"Ref": "Key"}}},
        }
    )
    _deploy_stack(ctx, good_stack_name, good_template)
    good_status = _wait_for_stack_status(ctx, good_stack_name)
    assert good_status == "CREATE_COMPLETE", f"positive control stack failed: {good_status}"

    good_key_id = _stack_outputs(ctx, good_stack_name)["KeyId"]
    described = kms.describe_key(KeyId=good_alias_name)["KeyMetadata"]
    assert described["KeyId"] == good_key_id, (
        f"expected alias {good_alias_name} to resolve to key {good_key_id}, got {described['KeyId']}"
    )
    ciphertext = kms.encrypt(KeyId=good_alias_name, Plaintext=b"sim2real-control")["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == b"sim2real-control", f"expected round-tripped plaintext, got {decrypted!r}"


def _deploy_stack(ctx: Any, stack_name: str, template_body: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, OnFailure="ROLLBACK")
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))


def _delete_stack(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_for_stack_gone(ctx, stack_name)


def _wait_for_stack_gone(ctx: Any, stack_name: str, timeout_s: float = 300.0, interval_s: float = 2.0) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} teardown failed: DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s")


def _wait_for_stack_status(ctx: Any, stack_name: str, timeout_s: float = 600.0, interval_s: float = 10.0) -> str:
    cfn = ctx.client("cloudformation")
    terminal = {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state in {timeout_s}s (last={status})")


def _stack_outputs(ctx: Any, stack_name: str) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = resp["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _stack_events(ctx: Any, stack_name: str) -> list[dict[str, Any]]:
    cfn = ctx.client("cloudformation")
    events: list[dict[str, Any]] = []
    paginator = cfn.get_paginator("describe_stack_events")
    for page in paginator.paginate(StackName=stack_name):
        events.extend(page.get("StackEvents", []))
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
