"""deploy-sns-topic-policy-lifecycle-then-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sns-topic-policy-lifecycle-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SNS::TopicPolicy reads back as the topic's Policy attribute;
    an update dropping it reverts the topic to SNS's default policy, and the stack delete removes
    the topic (NotFound)."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    topic_name = ctx.unique_name("sim2real-behav-topicpol-")
    stack_name = ctx.unique_name("sim2real-behav-topicpol-stack-")
    statement = {
        "Sid": "sim2real-allow-account-publish",
        "Effect": "Allow",
        "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
        "Action": "SNS:Publish",
        "Resource": {"Ref": "Topic"},
    }
    resources = {
        "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
        "Policy": {
            "Type": "AWS::SNS::TopicPolicy",
            "Properties": {
                "Topics": [{"Ref": "Topic"}],
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement]},
            },
        },
    }
    outputs_block = {"TopicArn": {"Value": {"Ref": "Topic"}}}
    template = json.dumps({"Resources": resources, "Outputs": outputs_block})
    without_policy = json.dumps({"Resources": {"Topic": resources["Topic"]}, "Outputs": outputs_block})

    cfn.create_stack(StackName=stack_name, TemplateBody=template,
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    topic_arn = outputs["TopicArn"]

    policy = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    matching = [s for s in policy["Statement"] if s.get("Sid") == "sim2real-allow-account-publish"]
    assert len(matching) == 1, f"expected exactly one matching statement, got {policy['Statement']!r}"
    got_stmt = matching[0]
    assert got_stmt["Effect"] == "Allow", f"Effect mismatch: {got_stmt!r}"
    assert got_stmt["Action"] == "SNS:Publish", f"Action mismatch: {got_stmt!r}"
    assert got_stmt["Resource"] == topic_arn, f"Resource mismatch: {got_stmt!r}"
    assert got_stmt["Principal"]["AWS"] == f"arn:aws:iam::{ctx.account}:root", (
        f"Principal mismatch: {got_stmt!r}"
    )

    # The policy's own removal, observed on the topic that outlives it.
    cfn.update_stack(StackName=stack_name, TemplateBody=without_policy,
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    reverted = json.loads(sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]["Policy"])
    shape = (reverted.get("Id"), [st.get("Sid") for st in reverted["Statement"]])
    assert shape == ("__default_policy_ID", ["__default_statement_ID"]), (
        f"after the update removed the TopicPolicy the topic's policy must be SNS's default, got {reverted!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    code, message = _error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert code == "NotFound", f"expected NotFound after stack delete, got {code!r}"
    assert message == "Topic does not exist", f"unexpected not-found message: {message!r}"


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
