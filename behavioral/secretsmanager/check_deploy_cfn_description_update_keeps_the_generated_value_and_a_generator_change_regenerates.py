"""deploy-cfn-description-update-keeps-the-generated-value-and-a-generator-change-regenerates."""
from __future__ import annotations

import json
import string
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-description-update-keeps-the-generated-value-and-a-generator-change-regenerates"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_DEPLOY_TIMEOUT_S = 300.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update changing only a GenerateSecretString secret's Description keeps its value and
    VersionId; changing the generator mints a new AWSCURRENT value obeying the new spec and leaves
    the old password readable as AWSPREVIOUS.
    """
    sm = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")
    secret_name = ctx.unique_name("sim2real-behav-cfngen-")

    def template(description, length):
        return json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {
                    "Generated": {
                        "Type": "AWS::SecretsManager::Secret",
                        "Properties": {
                            "Name": secret_name,
                            "Description": description,
                            "GenerateSecretString": {"PasswordLength": length, "ExcludePunctuation": True},
                            "Tags": [{"Key": "sim2real", "Value": CHECK}],
                        },
                    }
                },
                "Outputs": {"Arn": {"Value": {"Ref": "Generated"}}},
            }
        )

    stack_name = ctx.unique_name("sim2real-behav-cfngen-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.create_stack(StackName=stack_name, TemplateBody=template("sim2real first", 20))
    status = _wait_stack(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"the stack must deploy; it ended {status!r}: {_failures(cfn, stack_name)!r}"
    arn = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"][0]["OutputValue"]

    first = sm.get_secret_value(SecretId=arn)
    _assert_generated(first["SecretString"], 20)

    # Update 1: Description only.
    cfn.update_stack(StackName=stack_name, TemplateBody=template("sim2real second", 20))
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"the description update must apply; it ended {status!r}"
    described = sm.describe_secret(SecretId=arn)
    assert described["Description"] == "sim2real second", (
        f"the update must change the description; got {described.get('Description')!r}"
    )
    kept = sm.get_secret_value(SecretId=arn)
    assert (kept["VersionId"], kept["SecretString"]) == (first["VersionId"], first["SecretString"]), (
        "a description-only update must keep the generated value and its version; "
        f"version {kept['VersionId'] == first['VersionId']!r}, value {kept['SecretString'] == first['SecretString']!r}"
    )
    assert described["VersionIdsToStages"] == {first["VersionId"]: ["AWSCURRENT"]}, (
        f"a description-only update must mint no version; got {described['VersionIdsToStages']!r}"
    )

    # Update 2: the generator spec changes.
    cfn.update_stack(StackName=stack_name, TemplateBody=template("sim2real second", 32))
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", f"the generator update must apply; it ended {status!r}"
    # The current-value read is eventually consistent after a write: converge, never require lag.
    deadline = time.monotonic() + 60.0
    regenerated = sm.get_secret_value(SecretId=arn)
    while regenerated["VersionId"] == first["VersionId"] and time.monotonic() < deadline:
        time.sleep(2.0)
        regenerated = sm.get_secret_value(SecretId=arn)
    assert regenerated["VersionId"] != first["VersionId"], (
        "a generator change must mint a new AWSCURRENT version"
    )
    _assert_generated(regenerated["SecretString"], 32)
    previous = sm.get_secret_value(SecretId=arn, VersionStage="AWSPREVIOUS")
    assert (previous["VersionId"], previous["SecretString"]) == (first["VersionId"], first["SecretString"]), (
        "the original generated value must remain readable as AWSPREVIOUS"
    )


def _assert_generated(value, length):
    allowed = set(string.ascii_letters + string.digits)
    assert len(value) == length, f"the generated password must be {length} characters; got {len(value)}"
    stray = sorted(set(value) - allowed)
    assert not stray, f"ExcludePunctuation must leave only letters and digits; found {stray!r}"


def _wait_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)


def _failures(cfn, stack_name):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _delete_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
