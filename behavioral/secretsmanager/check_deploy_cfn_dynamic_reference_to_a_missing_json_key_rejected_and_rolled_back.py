"""deploy-cfn-dynamic-reference-to-a-missing-json-key-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamic-reference-to-a-missing-json-key-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_DEPLOY_TIMEOUT_S = 300.0


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A dynamic reference naming a JSON key the referenced secret does not hold fails the deploy:
    the stack rolls back, the secret it would have created does not exist, and the identical
    template naming a key the secret does hold deploys and receives that key's value.
    """
    sm = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")

    source = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-dynref-miss-src-"),
        SecretString=json.dumps({"username": "app", "password": "pw-value"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    source_arn = source["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=source_arn, ForceDeleteWithoutRecovery=True))

    def template(name, key):
        return json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {
                    "Copy": {
                        "Type": "AWS::SecretsManager::Secret",
                        "Properties": {
                            "Name": name,
                            "SecretString": f"{{{{resolve:secretsmanager:{source_arn}:SecretString:{key}}}}}",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}],
                        },
                    }
                },
            }
        )

    bad_name = ctx.unique_name("sim2real-behav-dynref-miss-bad-")
    bad_stack = ctx.unique_name("sim2real-behav-dynref-miss-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    cfn.create_stack(StackName=bad_stack, TemplateBody=template(bad_name, "no_such_key"))
    status = _wait_stack(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"a reference to a missing JSON key must roll the stack back; it ended {status!r}"
    )
    failures = _failures(cfn, bad_stack)
    assert failures == [
        ("Copy", "CREATE_FAILED", "Could not find a value associated with JSONKey in SecretString")
    ], f"the resource must fail on the unresolvable key and nothing else; failures were {failures!r}"
    code, message = _describe_code(sm, bad_name)
    assert code == "ResourceNotFoundException", (
        f"the rolled-back stack must leave no secret named {bad_name!r}; DescribeSecret gave {code!r}"
    )
    assert message == "Secrets Manager can't find the specified secret.", (
        f"unexpected DescribeSecret not-found message: {message!r}"
    )

    good_name = ctx.unique_name("sim2real-behav-dynref-miss-good-")
    good_stack = ctx.unique_name("sim2real-behav-dynref-ok-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    cfn.create_stack(StackName=good_stack, TemplateBody=template(good_name, "password"))
    status = _wait_stack(cfn, good_stack)
    assert status == "CREATE_COMPLETE", (
        f"the control naming an existing key must deploy; it ended {status!r}: {_failures(cfn, good_stack)!r}"
    )
    value = sm.get_secret_value(SecretId=good_name)["SecretString"]
    assert value == "pw-value", f"the control must receive the key's value; got {value!r}"


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


def _describe_code(sm, name):
    try:
        sm.describe_secret(SecretId=name)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "<exists>", None


def _delete_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
