"""deploy-iot-topic-rule-cfn-routes-messages."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-iot-topic-rule-cfn-routes-messages"
GROUP = "deploy"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::IoT::TopicRule republish action really forwards
    a matching MQTT publish to the target topic (observed via a second rule that
    drains the republished topic into SQS), not merely reaches CREATE_COMPLETE."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    cfn = ctx.client("cloudformation")

    account = sts.get_caller_identity()["Account"]
    region = ctx.region
    base_topic = ctx.unique_name("sim2real-iot-topic").replace("-", "")
    topic_in = f"{base_topic}/in"
    topic_out = f"{base_topic}/out"

    # queue that the second (plain-API) rule drains the republished topic into
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iot-ota-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # role usable by both the republish action and the sqs action
    role_name = ctx.unique_name("sim2real-iot-rule-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "iot:Publish", "Resource": f"arn:aws:iot:{region}:{account}:topic/{base_topic}/*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline"))

    rule_in_name = _safe_rule_name(ctx.unique_name("s2r_rule_in_"))
    rule_out_name = _safe_rule_name(ctx.unique_name("s2r_rule_out_"))

    # rule2 (plain API): drains the republished "out" topic into SQS, so we can
    # observe the republish action's effect purely through the AWS API.
    _wait_role_usable(
        lambda: iot.create_topic_rule(
            ruleName=rule_out_name,
            topicRulePayload={
                "sql": f"SELECT * FROM '{topic_out}'",
                "awsIotSqlVersion": "2016-03-23",
                "actions": [{"sqs": {"roleArn": role_arn, "queueUrl": queue_url, "useBase64": False}}],
            },
            tags=f"sim2real={CHECK}",
        )
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_out_name))

    # rule1 (the system under test): deployed via CloudFormation, republishes "in" -> "out"
    stack_name = ctx.unique_name("sim2real-iot-cfn-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TopicRule": {
                "Type": "AWS::IoT::TopicRule",
                "Properties": {
                    "RuleName": rule_in_name,
                    "TopicRulePayload": {
                        "Sql": f"SELECT * FROM '{topic_in}'",
                        "AwsIotSqlVersion": "2016-03-23",
                        "RuleDisabled": False,
                        "Actions": [{"Republish": {"RoleArn": role_arn, "Topic": topic_out}}],
                    },
                },
            }
        },
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    # confirm the CFN-created rule is actually the republish rule we asked for
    fetched = iot.get_topic_rule(ruleName=rule_in_name)["rule"]
    fetched_topic = fetched["actions"][0]["republish"]["topic"]
    assert fetched_topic == topic_out, (
        f"CFN-created rule's republish target topic was {fetched_topic!r}, expected {topic_out!r}"
    )

    # exercise the data plane: publish to "in" and observe it arrive on "out" via SQS
    iot_data = _iot_data_client(ctx, iot)
    payload = {"marker": ctx.unique_name("sim2real-marker-")}
    iot_data.publish(topic=topic_in, qos=0, payload=json.dumps(payload).encode("utf-8"))

    delivered = _poll_for_sqs_message(sqs, queue_url, timeout_s=60.0)
    assert delivered is not None, "republished message never arrived on the destination topic's SQS drain"
    body = json.loads(delivered)
    assert body.get("marker") == payload["marker"], (
        f"delivered marker was {body.get('marker')!r}, expected {payload['marker']!r}"
    )


def _safe_rule_name(name: str) -> str:
    return name.replace("-", "_")


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _wait_role_usable(fn, attempts: int = 6, delay_s: float = 5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM eventual consistency retry
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _iot_data_client(ctx, iot):
    """iot-data must hit the account-specific ATS data-plane endpoint on real AWS -- the
    control-plane host does not serve Publish. Every target publishes it through DescribeEndpoint."""
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


def _poll_for_sqs_message(sqs, queue_url, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
