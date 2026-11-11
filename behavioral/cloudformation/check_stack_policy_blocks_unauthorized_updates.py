"""stack-policy-blocks-unauthorized-updates."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-policy-blocks-unauthorized-updates"
GROUP = 'stack_update'
SERVICES = ['cloudformation']


def _describe_stack(cf, name):
    stacks = cf.describe_stacks(StackName=name).get("Stacks", [])
    return stacks[0] if stacks else None

def _wait_stack(cf, name, targets, timeout_s=180):
    """Poll DescribeStacks until StackStatus is in `targets`; return the stack dict."""
    deadline = time.monotonic() + timeout_s
    stack = None
    while time.monotonic() < deadline:
        try:
            stack = _describe_stack(cf, name)
        except ClientError:
            stack = None
        if stack is not None and stack.get("StackStatus") in targets:
            return stack
        time.sleep(3)
    raise AssertionError(f"stack {name} did not reach {targets} within {timeout_s}s (last={stack})")

def _named_topic_template(topic_name, tags=None):
    """Explicit TopicName — changing it forces AWS::SNS::Topic REPLACEMENT."""
    props = {"TopicName": topic_name}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )

def _allow_all_deny_replace_policy(logical_id):
    return json.dumps(
        {
            "Statement": [
                {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
                {
                    "Effect": "Deny",
                    "Action": "Update:Replace",
                    "Principal": "*",
                    "Resource": f"LogicalResourceId/{logical_id}",
                },
            ]
        }
    )

def _allow_all_policy():
    return json.dumps({"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]})

def _poll_until_gone(sns, topic_arn, timeout_s=60, interval_s=3):
    """Poll GetTopicAttributes until it reports NotFound; raise on any other outcome/timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_arn} still exists after {timeout_s}s: {last}")

def _assert_topic_missing(sns, topic_arn):
    try:
        attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "NotFound", f"expected NotFound for {topic_arn}, got {err}"
        assert err.get("Message") == "Topic does not exist", err
    else:
        raise AssertionError(f"topic {topic_arn} must not exist, got {attrs}")


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack policy denying Update:Replace on a topic blocks a replacing update while a Tags-only
    update still applies, both confirmed at SNS; once the Deny is lifted the same update succeeds.
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-policy-deny-")
    topic_name_a = ctx.unique_name("sim2real-behav-topic-a-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=_named_topic_template(topic_name_a))["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
    _wait_stack(cf, name, {"CREATE_COMPLETE"})

    outputs = cf.describe_stacks(StackName=name)["Stacks"][0]["Outputs"]
    topic_arn_a = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "TopicArn")
    arn_prefix = topic_arn_a.rsplit(":", 1)[0]

    policy_body = _allow_all_deny_replace_policy("Topic")
    cf.set_stack_policy(StackName=name, StackPolicyBody=policy_body)

    fetched = cf.get_stack_policy(StackName=name)
    assert json.loads(fetched["StackPolicyBody"]) == json.loads(policy_body), (
        f"GetStackPolicy returned {fetched.get('StackPolicyBody')!r}, expected {policy_body!r}"
    )

    # A non-replacing update (Tags only) is still allowed by the wildcard Allow.
    cf.update_stack(
        StackName=name, TemplateBody=_named_topic_template(topic_name_a, tags={"phase": "2"})
    )
    allowed = _wait_stack(
        cf, name, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"}
    )
    assert allowed["StackStatus"] == "UPDATE_COMPLETE", allowed.get("StackStatusReason")
    tags_after = sns.list_tags_for_resource(ResourceArn=topic_arn_a)["Tags"]
    assert {"Key": "phase", "Value": "2"} in tags_after, (
        f"tags-only update was allowed by CloudFormation but never reached SNS: {tags_after}"
    )

    # A TopicName change forces replacement; CloudFormation accepts the update, then the stack
    # policy fails the Topic resource and the stack rolls back.
    topic_name_b = ctx.unique_name("sim2real-behav-topic-b-")
    topic_arn_b = f"{arn_prefix}:{topic_name_b}"
    cf.update_stack(StackName=name, TemplateBody=_named_topic_template(topic_name_b))
    denied = _wait_stack(
        cf,
        name,
        {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=180,
    )
    assert denied["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"a Deny Update:Replace stack policy must roll the replacing update back, got "
        f"{denied['StackStatus']!r}"
    )
    reasons = [
        e.get("ResourceStatusReason")
        for e in cf.describe_stack_events(StackName=name)["StackEvents"]
        if e["LogicalResourceId"] == "Topic" and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    expected_reason = (
        "Action denied by stack policy: Statement [#1] does not allow [Update:Replace] "
        "for resource [LogicalResourceId/Topic];"
    )
    assert reasons == [expected_reason], (
        f"the Topic's UPDATE_FAILED events carry {reasons!r}, expected [{expected_reason!r}]"
    )

    still_there = sns.get_topic_attributes(TopicArn=topic_arn_a)["Attributes"]
    assert still_there["TopicArn"] == topic_arn_a, (
        f"the policy-protected topic must not have been replaced, got {still_there}"
    )
    _assert_topic_missing(sns, topic_arn_b)

    cf.set_stack_policy(StackName=name, StackPolicyBody=_allow_all_policy())
    cf.update_stack(StackName=name, TemplateBody=_named_topic_template(topic_name_b))
    restored = _wait_stack(
        cf, name, {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"}, timeout_s=180
    )
    assert restored["StackStatus"] == "UPDATE_COMPLETE", (
        f"the identical replacing update must succeed once the deny policy is lifted, got {restored}"
    )
    replaced = sns.get_topic_attributes(TopicArn=topic_arn_b)["Attributes"]
    assert replaced["TopicArn"] == topic_arn_b, (
        f"the topic must have been replaced under the new name once permitted, got {replaced}"
    )
    _poll_until_gone(sns, topic_arn_a)


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
