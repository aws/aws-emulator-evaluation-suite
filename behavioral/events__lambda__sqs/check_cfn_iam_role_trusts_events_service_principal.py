"""cfn-iam-role-trusts-events-service-principal."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-trusts-events-service-principal"
GROUP = "iam-trust"
SERVICES = ["events", "lambda", "sqs"]

_ROLE_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RoleNameParam": {"Type": "String"},
            "StreamArnParam": {"Type": "String"},
        },
        "Resources": {
            "EventsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleNameParam"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "PutRecordToStream",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "kinesis:PutRecord",
                                        "Resource": {"Ref": "StreamArnParam"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["EventsRole", "Arn"]}}},
    }
)


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN role trusting events.amazonaws.com is really assumed by EventBridge: a rule
    with a Kinesis-stream target using RoleArn only delivers if the trust holds, since
    Kinesis targets (unlike Lambda/SQS) are invoked via role assumption, not resource policy."""
    kinesis = ctx.client("kinesis")
    events = ctx.client("events")

    stream_name = _xname(ctx, "trust-stream")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags=_xsvc_resource_tags()
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(
            StreamName=stream_name, EnforceConsumerDeletion=True
        )
    )
    stream_desc = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=3.0,
        description=f"kinesis stream {stream_name} ACTIVE",
    )
    stream_arn = stream_desc["StreamARN"]

    role_name = _xname(ctx, "events-trust-role")
    result = _deploy_cfn(
        ctx,
        _ROLE_TEMPLATE,
        parameters={"RoleNameParam": role_name, "StreamArnParam": stream_arn},
    )
    role_arn = result["outputs"]["RoleArn"]
    assert role_arn.endswith(f":role/{role_name}")

    rule_name = _xname(ctx, "events-trust-rule")
    source = _xname(ctx, "src")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": ["TrustTest"]}),
        State="ENABLED",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    marker = ctx.unique_name("trust-marker-")

    def _put_target():
        return events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": "kinesis-target",
                    "Arn": stream_arn,
                    "RoleArn": role_arn,
                    "KinesisParameters": {"PartitionKeyPath": "$.detail.id"},
                }
            ],
        )

    # IAM role propagation is eventually consistent; retry PutTargets until EventBridge
    # accepts the RoleArn (it validates assumability at target-registration time).
    put_result = _poll_until(
        _put_target,
        lambda r: r.get("FailedEntryCount", 0) == 0,
        timeout_s=60,
        interval_s=3.0,
        description="put_targets accepts events-trust role",
    )
    assert put_result["FailedEntryCount"] == 0
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, Ids=["kinesis-target"])
    )

    events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "TrustTest",
                "Detail": json.dumps({"id": marker, "payload": "hello-kinesis"}),
            }
        ]
    )

    shards = kinesis.list_shards(StreamName=stream_name)["Shards"]
    shard_iter = kinesis.get_shard_iterator(
        StreamName=stream_name,
        ShardId=shards[0]["ShardId"],
        ShardIteratorType="TRIM_HORIZON",
    )["ShardIterator"]

    def _find_record():
        nonlocal shard_iter
        resp = kinesis.get_records(ShardIterator=shard_iter, Limit=50)
        shard_iter = resp["NextShardIterator"]
        for rec in resp["Records"]:
            data = json.loads(rec["Data"])
            if data.get("detail", {}).get("id") == marker:
                return data
        return None

    delivered = _poll_until(
        _find_record,
        lambda d: d is not None,
        timeout_s=60,
        interval_s=3.0,
        description=f"kinesis record for marker {marker}",
    )
    assert delivered["detail"]["payload"] == "hello-kinesis"
    assert delivered["source"] == source


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
