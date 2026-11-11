"""secretsmanager-secretstring-writeonly-update-hidden-from-cloudcontrol."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secretsmanager-secretstring-writeonly-update-hidden-from-cloudcontrol"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "cloudformation", "secretsmanager"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _template(secret_name: str, secret_string: str) -> str:
    return json.dumps({
        "Resources": {
            "Secret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"Name": secret_name, "SecretString": secret_string},
            }
        }
    })


def _wait_terminal(cf, stack, *, timeout_s=300.0, interval_s=2.0):
    """Poll DescribeStacks to a terminal StackStatus; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        s = cf.describe_stacks(StackName=stack)["Stacks"][0]
        if s["StackStatus"] in _TERMINAL:
            return s
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack} stuck at {s['StackStatus']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _wait_change_set(cf, stack, name, *, timeout_s=180.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        r = cf.describe_change_set(StackName=stack, ChangeSetName=name)
        if r["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return r
        if time.monotonic() >= deadline:
            raise AssertionError(f"change set {name} stuck at {r['Status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_stack(cf, stack: str) -> None:
    """Delete the stack and wait; raise unless it ends DELETE_COMPLETE."""
    # Wait on the stack id: a deleted stack answers DescribeStacks by id with DELETE_COMPLETE,
    # and by name with "does not exist".
    stack_id = cf.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    cf.delete_stack(StackName=stack_id)
    final = _wait_terminal(cf, stack_id)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack} delete ended {final['StackStatus']!r}: {final.get('StackStatusReason')!r}"
        )


def _assert_populated(props: dict, secret_name: str, secret_arn: str, when: str) -> None:
    """The model carries the readable Name and Id, so an absence in it can fail."""
    assert (props.get("Name"), props.get("Id")) == (secret_name, secret_arn), (
        f"{when}: GetResource model lacks the readable Name/Id of the secret: {props!r}"
    )


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:deploy", "concern:representation",
    "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A CFN-declared AWS::SecretsManager::Secret SecretString is accepted and stored, never
    reported in Cloud Control's GetResource ResourceModel, and a change set touching only it is
    classified Replacement=False/RequiresRecreation=Never and applies in place.
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    cc = ctx.client("cloudcontrol")

    stack = ctx.unique_name("sim2real-behav-secwo-")
    secret_name = ctx.unique_name("sim2real-behav-secwo-secret-")

    cf.create_stack(
        StackName=stack, TemplateBody=_template(secret_name, "v1-secret-value"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )

    secret_arn = cf.list_stack_resources(StackName=stack)["StackResourceSummaries"][0][
        "PhysicalResourceId"
    ]

    # The write-only value was accepted and takes effect, proven through the owning service.
    assert sm.get_secret_value(SecretId=secret_arn)["SecretString"] == "v1-secret-value", (
        "the declared SecretString must be stored and readable through Secrets Manager"
    )
    created_date = sm.describe_secret(SecretId=secret_arn)["CreatedDate"]

    # Absence from Cloud Control's ResourceModel: the read must SUCCEED (so the assert can fail)
    # and the returned model must not carry the write-only property.
    model_before = cc.get_resource(TypeName="AWS::SecretsManager::Secret", Identifier=secret_arn)
    props_before = json.loads(model_before["ResourceDescription"]["Properties"])
    _assert_populated(props_before, secret_name, secret_arn, "before the update")
    assert "SecretString" not in props_before, (
        f"GetResource must never report the write-only SecretString, got {props_before!r}"
    )

    cs_name = ctx.unique_name("sim2real-behav-secwo-cs-")
    cf.create_change_set(
        StackName=stack, ChangeSetName=cs_name,
        TemplateBody=_template(secret_name, "v2-secret-value"),
    )
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_change_set(StackName=stack, ChangeSetName=cs_name),
        "ChangeSetNotFound",
    ))
    cs = _wait_change_set(cf, stack, cs_name)
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    changes = cs.get("Changes", [])
    assert len(changes) == 1, f"expected exactly one resource change, got {len(changes)}: {changes!r}"
    rc = changes[0]["ResourceChange"]
    assert rc["Action"] == "Modify", f"expected Action=Modify, got {rc['Action']!r}"
    assert rc.get("Replacement") == "False", (
        f"a SecretString-only change must be classified Replacement=False, got {rc.get('Replacement')!r}"
    )
    details = rc.get("Details", [])
    assert len(details) == 1, f"expected exactly one changed-property detail, got {details!r}"
    target = details[0]["Target"]
    assert target["Name"] == "SecretString", f"expected the detail to name SecretString, got {target!r}"
    assert target["Attribute"] == "Properties", target
    assert target["RequiresRecreation"] == "Never", (
        f"a non-create-only write-only property must report RequiresRecreation=Never, got {target!r}"
    )
    assert details[0].get("Evaluation") == "Static", (
        f"expected Evaluation=Static, got {details[0].get('Evaluation')!r}"
    )
    assert details[0].get("ChangeSource") == "DirectModification", (
        f"expected ChangeSource=DirectModification, got {details[0].get('ChangeSource')!r}"
    )

    cf.execute_change_set(StackName=stack, ChangeSetName=cs_name)
    executed = _wait_terminal(cf, stack)
    assert executed["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {executed['StackStatus']!r}: {executed.get('StackStatusReason')!r}"
    )

    # The new write-only value took effect...
    assert sm.get_secret_value(SecretId=secret_arn)["SecretString"] == "v2-secret-value", (
        "the updated SecretString must be stored and readable through Secrets Manager"
    )
    # ...the resource was updated IN PLACE, proven by a value Secrets Manager mints once at
    # creation and never changes thereafter (unlike the name-derived ARN, which a replacement
    # using the same literal Name would also preserve).
    assert sm.describe_secret(SecretId=secret_arn)["CreatedDate"] == created_date, (
        "CreatedDate must be unchanged after an in-place update; a changed value would mean the "
        "secret was actually destroyed and recreated despite Replacement=False"
    )
    # And the write-only value stays hidden from the resource model after the update too.
    model_after = cc.get_resource(TypeName="AWS::SecretsManager::Secret", Identifier=secret_arn)
    props_after = json.loads(model_after["ResourceDescription"]["Properties"])
    _assert_populated(props_after, secret_name, secret_arn, "after the update")
    assert "SecretString" not in props_after, (
        f"GetResource must never report the write-only SecretString, got {props_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
