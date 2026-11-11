"""deploy-topic-rule-cfn-routes-matching-messages."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-topic-rule-cfn-routes-matching-messages"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TopicRule deployed via CloudFormation with a SQL WHERE filter routes only the
    matching MQTT message to its SQS action; the non-matching message is never delivered."""
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    queue_name = ctx.unique_name("sim2real-topicrule-q-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": "behavioral"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    role_name = ctx.unique_name("sim2real-topicrule-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    send_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="send-to-queue", PolicyDocument=json.dumps(send_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="send-to-queue"))

    rule_name = ctx.unique_name("sim2real_topicrule_")
    topic = f"sim2real/{rule_name}"
    sql = f"SELECT * FROM '{topic}' WHERE match = 'yes'"
    stack_name = ctx.unique_name("sim2real-topicrule-stack-")
    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "TopicRule": {
                    "Type": "AWS::IoT::TopicRule",
                    "Properties": {
                        "RuleName": rule_name,
                        "TopicRulePayload": {
                            "Sql": sql,
                            "RuleDisabled": False,
                            "Actions": [
                                {"Sqs": {"QueueUrl": queue_url, "RoleArn": role_arn, "UseBase64": False}}
                            ],
                        },
                    },
                }
            },
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_for_stack_create_with_retry(cfn, stack_name, template_body)

    # Sanity: the rule the stack created is fetchable and carries the SQL we asked for.
    rule = iot.get_topic_rule(ruleName=rule_name)["rule"]
    assert rule["sql"] == sql, f"expected rule sql {sql!r}, got {rule['sql']!r}"

    iot_data = _iot_data_client(ctx)
    matching_marker = ctx.unique_name("match-")
    other_marker = ctx.unique_name("nomatch-")
    iot_data.publish(
        topic=topic, qos=1, payload=json.dumps({"match": "yes", "marker": matching_marker}).encode()
    )
    iot_data.publish(
        topic=topic, qos=1, payload=json.dumps({"match": "no", "marker": other_marker}).encode()
    )

    # Poll the full window regardless of when the match shows up: stopping as soon as
    # found_match flips true would let a permissive target that queues the non-matching
    # message with extra latency slip past the negative assertion below.
    seen_bodies: list[str] = []
    deadline = time.monotonic() + 45
    found_match = False
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen_bodies.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if matching_marker in msg["Body"]:
                found_match = True

    assert found_match, f"matching message never reached the queue; saw: {seen_bodies}"
    assert not any(other_marker in b for b in seen_bodies), (
        "the non-matching message was routed to the queue despite the SQL WHERE filter"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """DeleteStack is idempotent and the waiter treats a missing stack as deleted."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _wait_for_stack_create_with_retry(cfn, stack_name: str, template_body: str, attempts: int = 3) -> None:
    """CreateTopicRule with an Sqs action validates that IoT can assume the action's RoleArn at
    creation time; a role/policy created moments earlier can still be lagging on IAM's
    eventual-consistency window, which rolls the stack back with no useful CFN-level retry.
    Recreate the stack a few times, giving IAM time to propagate, rather than treating that
    transient rollback as a template bug."""
    last_status = None
    last_reason = None
    for attempt in range(attempts):
        try:
            cfn.get_waiter("stack_create_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
            return
        except Exception:  # noqa: BLE001
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            failed = [e for e in events if e.get("ResourceStatus", "").endswith("FAILED")]
            last_reason = failed[0]["ResourceStatusReason"] if failed else "unknown"
            last_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            if attempt == attempts - 1:
                raise AssertionError(
                    f"stack failed to reach CREATE_COMPLETE after {attempts} attempts "
                    f"(status={last_status}, reason={last_reason})"
                )
            _delete_stack(cfn, stack_name)
            time.sleep(10 * (attempt + 1))
            cfn.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Tags=[{"Key": "sim2real", "Value": "behavioral"}],
            )


# ===== helpers =====
def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
