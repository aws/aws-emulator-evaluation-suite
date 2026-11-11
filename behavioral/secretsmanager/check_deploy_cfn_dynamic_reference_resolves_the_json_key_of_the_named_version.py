"""deploy-cfn-dynamic-reference-resolves-the-json-key-of-the-named-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamic-reference-resolves-the-json-key-of-the-named-version"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_DEPLOY_TIMEOUT_S = 300.0


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A {{resolve:secretsmanager:...}} reference deploys the JSON key of exactly the version it
    names: AWSCURRENT by default, AWSPREVIOUS by stage, the first version by VersionId; a later
    write to the source does not change what was deployed.
    """
    sm = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")

    source = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-dynref-src-"),
        SecretString=json.dumps({"username": "app", "password": "first-password"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    source_arn = source["ARN"]
    first_version = source["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=source_arn, ForceDeleteWithoutRecovery=True))
    second_version = sm.put_secret_value(
        SecretId=source_arn,
        SecretString=json.dumps({"username": "app", "password": "second-password"}),
    )["VersionId"]
    stages = sm.describe_secret(SecretId=source_arn)["VersionIdsToStages"]
    assert stages == {first_version: ["AWSPREVIOUS"], second_version: ["AWSCURRENT"]}, (
        f"the source must hold AWSCURRENT on the second write and AWSPREVIOUS on the first; got {stages!r}"
    )

    names = {
        "Current": ctx.unique_name("sim2real-behav-dynref-cur-"),
        "Previous": ctx.unique_name("sim2real-behav-dynref-prev-"),
        "ById": ctx.unique_name("sim2real-behav-dynref-byid-"),
    }
    refs = {
        "Current": f"{{{{resolve:secretsmanager:{source_arn}:SecretString:password}}}}",
        "Previous": f"{{{{resolve:secretsmanager:{source_arn}:SecretString:password:AWSPREVIOUS}}}}",
        "ById": f"{{{{resolve:secretsmanager:{source_arn}:SecretString:password::{first_version}}}}}",
    }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            logical: {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {
                    "Name": names[logical],
                    "SecretString": refs[logical],
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            }
            for logical in names
        },
        "Outputs": {logical: {"Value": {"Ref": logical}} for logical in names},
    }
    stack_name = ctx.unique_name("sim2real-behav-dynref-")
    # Registered before the create so a failed or slow deploy is still torn down.
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    status = _wait_stack(cfn, stack_name)
    assert status == "CREATE_COMPLETE", f"the stack must deploy; it ended {status!r}: {_failures(cfn, stack_name)!r}"
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }

    deployed = {k: sm.get_secret_value(SecretId=outputs[k])["SecretString"] for k in names}
    assert deployed == {
        "Current": "second-password",
        "Previous": "first-password",
        "ById": "first-password",
    }, f"each reference must resolve the password of the version it names; got {deployed!r}"

    # Resolution happened at deploy time: a later write to the source changes nothing deployed.
    sm.put_secret_value(
        SecretId=source_arn,
        SecretString=json.dumps({"username": "app", "password": "third-password"}),
    )
    after = {k: sm.get_secret_value(SecretId=outputs[k])["SecretString"] for k in names}
    assert after == deployed, f"a write to the source after the deploy must not alter the deployed values; got {after!r}"


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
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
