"""deploy-security-policy-cfn-enforced."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-security-policy-cfn-enforced"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed encryption SecurityPolicy is actually enforced on a
    same-stack collection that declares no EncryptionConfig of its own -- the collection
    can only reach ACTIVE if the policy was truly applied."""
    cfn = ctx.client("cloudformation")
    aoss = ctx.client("opensearchserverless")
    stack_name = ctx.unique_name("sim2real-aoss-secpol-stack-")
    prefix = _short_name(ctx, "sim2real-secpolcoll")
    policy_name = _short_name(ctx, "sim2real-secpol")

    policy_doc = json.dumps(
        {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{prefix}*"]}], "AWSOwnedKey": True}
    )

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "EncPolicy": {
                    "Type": "AWS::OpenSearchServerless::SecurityPolicy",
                    "Properties": {
                        "Name": policy_name,
                        "Type": "encryption",
                        "Policy": policy_doc,
                    },
                },
                "Collection": {
                    "Type": "AWS::OpenSearchServerless::Collection",
                    "DependsOn": "EncPolicy",
                    "Properties": {"Name": prefix, "Type": "SEARCH"},
                },
            },
            "Outputs": {"CollectionId": {"Value": {"Ref": "Collection"}}},
        }
    )

    stack_id = _deploy_cfn(ctx, cfn, stack_name, template, timeout_s=900)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }
    collection_id = outputs["CollectionId"]

    policy = aoss.get_security_policy(type="encryption", name=policy_name)["securityPolicyDetail"]
    parsed_policy = json.loads(policy["policy"]) if isinstance(policy["policy"], str) else policy["policy"]
    assert parsed_policy == json.loads(policy_doc), f"expected policy {policy_doc!r}, got {parsed_policy!r}"

    details = aoss.batch_get_collection(ids=[collection_id])["collectionDetails"]
    assert len(details) == 1, f"expected exactly 1 collection detail, got {len(details)}"
    assert details[0]["status"] == "ACTIVE", f"expected ACTIVE, got {details[0]['status']!r}"
    assert details[0]["name"] == prefix, f"expected name {prefix!r}, got {details[0]['name']!r}"


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _deploy_cfn(ctx: Any, cfn: Any, stack_name: str, template_body: str, *, timeout_s: float) -> str:

    def _cleanup() -> None:
        try:
            cfn.delete_stack(StackName=stack_id)
            _poll_until(
                lambda: _stack_status(cfn, stack_id),
                lambda s: s in (None, "DELETE_COMPLETE"),
                timeout_s=timeout_s,
                interval_s=15,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["StackId"]
    ctx.on_cleanup(_cleanup)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_id),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE"),
        timeout_s=timeout_s,
        interval_s=15,
    )
    assert status == "CREATE_COMPLETE", f"stack ended in {status}"
    return stack_id


def _stack_status(cfn: Any, stack_id: str) -> str | None:
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except Exception:
        return None


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
