"""deploy-cfn-msk-topic-round-trip-and-delete."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-msk-topic-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "kafka"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_CREATE_BUDGET_S = 2700.0  # a provisioned MSK cluster reaches ACTIVE within 45 min
_DELETE_BUDGET_S = 1700.0  # cleanup's own budget, separate from the check's run budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0, ctx=None):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone". With ``ctx``, a wait
    the run budget ended raises TimeoutError.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id, timeout_s=_DELETE_BUDGET_S, ctx=None):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + timeout_s
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic(), ctx)
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic(), ctx
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_CLUSTER_GONE = ("NotFoundException", "The requested resource doesn’t exist.")
_TOPIC_GONE = ("NotFoundException", "The requested resource doesn’t exist.")
# A ZooKeeper-mode version Standard brokers and the topic APIs both support.
_KAFKA_VERSION = "3.9.x"

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterName: {Type: String}
  TopicName: {Type: String}
  KafkaVersion: {Type: String}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.97.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.97.0.0/24
      AvailabilityZone: !Select [0, !GetAZs ""]
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.97.1.0/24
      AvailabilityZone: !Select [1, !GetAZs ""]
  ClusterSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real msk topic provisioning sg
      VpcId: !Ref Vpc
  MskCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.m5.large
        ClientSubnets: [!Ref SubnetA, !Ref SubnetB]
        SecurityGroups: [!Ref ClusterSG]
  MskTopic:
    Type: AWS::MSK::Topic
    Properties:
      ClusterArn: !Ref MskCluster
      TopicName: !Ref TopicName
      PartitionCount: 3
      ReplicationFactor: 2
Outputs:
  ClusterArn:
    Value: !Ref MskCluster
  TopicArnRef:
    Value: !Ref MskTopic
  TopicArnGetAtt:
    Value: !GetAtt MskTopic.TopicArn
"""

# Removes only the Topic resource (and its outputs), leaving the cluster running, so the topic's
# own deletion can be observed through Kafka's API without the cluster disappearing at the same
# moment and confounding the read.
_TEMPLATE_CLUSTER_ONLY = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  ClusterName: {Type: String}
  KafkaVersion: {Type: String}
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.97.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.97.0.0/24
      AvailabilityZone: !Select [0, !GetAZs ""]
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.97.1.0/24
      AvailabilityZone: !Select [1, !GetAZs ""]
  ClusterSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real msk topic provisioning sg
      VpcId: !Ref Vpc
  MskCluster:
    Type: AWS::MSK::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      KafkaVersion: !Ref KafkaVersion
      NumberOfBrokerNodes: 2
      BrokerNodeGroupInfo:
        InstanceType: kafka.m5.large
        ClientSubnets: [!Ref SubnetA, !Ref SubnetB]
        SecurityGroups: [!Ref ClusterSG]
Outputs:
  ClusterArn:
    Value: !Ref MskCluster
"""


def update_stack(ctx, cf, stack_id, template, timeout_s, **kw):
    """UpdateStack by StackId, waited to UPDATE_COMPLETE within ``timeout_s``."""
    cf.update_stack(StackName=stack_id, TemplateBody=template, **kw)
    status = wait_stack(
        cf,
        stack_id,
        {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"},
        timeout_s=timeout_s,
        ctx=ctx,
    )
    if status != "UPDATE_COMPLETE":
        events = decisive_rows(stack_events(cf, stack_id))
        raise AssertionError(f"stack {stack_id} update ended {status!r}: {events!r}")


def _clusters(kafka, name: str) -> list[dict]:
    """The clusters named exactly ``name`` (the filter is a prefix), every page."""
    return [
        c
        for c in paginate(kafka, "list_clusters_v2", "ClusterInfoList", ClusterNameFilter=name)
        if c["ClusterName"] == name
    ]


def _topics(kafka, cluster_arn: str, name: str) -> list[dict]:
    """The topics named exactly ``name`` on ``cluster_arn`` (the filter is a prefix), every page."""
    return [
        t
        for t in paginate(
            kafka, "list_topics", "Topics", ClusterArn=cluster_arn, TopicNameFilter=name
        )
        if t["TopicName"] == name
    ]


def _wait_topic_active(ctx, kafka, cluster_arn: str, topic_name: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        last = info["Status"]
        if last == "ACTIVE":
            return info
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"topic {topic_name!r} reaching ACTIVE: the run budget ended first; not graded"
        )
    raise AssertionError(f"topic {topic_name!r} never reached ACTIVE (last status {last!r})")


def _wait_topic_gone(ctx, kafka, cluster_arn: str, topic_name: str, timeout_s: float) -> None:
    """Poll DescribeTopic until it answers exactly _TOPIC_GONE; any other error propagates."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)["Status"]
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got == _TOPIC_GONE:
                return
            raise
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"topic {topic_name!r} disappearing: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"DescribeTopic still finds {topic_name!r} (status {last!r}) after the removal"
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::MSK::Topic is a real topic on the AWS::MSK::Cluster it names, its
    Ref and GetAtt matching what ListTopics and DescribeTopic report, and removing the Topic
    resource from the stack makes it disappear from both while its cluster stays ACTIVE."""
    cfn = ctx.client("cloudformation")
    kafka = ctx.client("kafka")
    cluster_name = ctx.unique_name("sim2real-mskcfn-")
    topic_name = ctx.unique_name("sim2real-topic-")

    kafka_version = _KAFKA_VERSION
    stack_name = ctx.unique_name("sim2real-mskcfn-topic-stack-")
    stack_id = create_stack(
        ctx,
        cfn,
        stack_name,
        _TEMPLATE,
        Parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
            {"ParameterKey": "TopicName", "ParameterValue": topic_name},
            {"ParameterKey": "KafkaVersion", "ParameterValue": kafka_version},
        ],
    )
    status = wait_stack(cfn, stack_id, timeout_s=_budget_s(ctx, _CREATE_BUDGET_S), ctx=ctx)
    if status != "CREATE_COMPLETE":
        events = stack_events(cfn, stack_id)
        fail_reasons = [
            e.get("ResourceStatusReason", "")
            for e in events
            if e["ResourceStatus"] == "CREATE_FAILED"
        ]
        raise AssertionError(
            f"stack {stack_id} ended {status!r} with KafkaVersion={kafka_version!r}: "
            f"{decisive_rows(events)!r}; failure reasons: {fail_reasons!r}"
        )

    outputs = stack_outputs(cfn, stack_id)
    cluster_arn = outputs["ClusterArn"]

    found_clusters = [c["ClusterArn"] for c in _clusters(kafka, cluster_name)]
    assert found_clusters == [cluster_arn], (
        f"ListClustersV2 lists {found_clusters!r} for {cluster_name!r}, expected [{cluster_arn!r}]"
    )
    cluster_info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert cluster_info["State"] == "ACTIVE", (
        f"cluster is {cluster_info['State']!r} right after stack CREATE_COMPLETE"
    )

    topic_info = _wait_topic_active(
        ctx, kafka, cluster_arn, topic_name, timeout_s=_budget_s(ctx, 300.0)
    )
    got = {
        "TopicArn": topic_info["TopicArn"],
        "TopicName": topic_info["TopicName"],
        "PartitionCount": topic_info["PartitionCount"],
        "ReplicationFactor": topic_info["ReplicationFactor"],
    }
    want = {
        "TopicArn": outputs["TopicArnRef"],
        "TopicName": topic_name,
        "PartitionCount": 3,
        "ReplicationFactor": 2,
    }
    assert got == want, f"DescribeTopic reads {got!r}, expected {want!r}"
    assert outputs["TopicArnRef"] == outputs["TopicArnGetAtt"], (
        f"Ref and Fn::GetAtt TopicArn disagree: {outputs['TopicArnRef']!r} != "
        f"{outputs['TopicArnGetAtt']!r}"
    )

    found_topics = [t["TopicArn"] for t in _topics(kafka, cluster_arn, topic_name)]
    assert found_topics == [outputs["TopicArnRef"]], (
        f"ListTopics lists {found_topics!r} for {topic_name!r}, "
        f"expected [{outputs['TopicArnRef']!r}]"
    )

    # Remove only the Topic resource, keeping the cluster ACTIVE, so the topic's own removal
    # reads cleanly: a describe against a still-existing cluster, not one torn down at the
    # same moment.
    update_stack(
        ctx,
        cfn,
        stack_id,
        _TEMPLATE_CLUSTER_ONLY,
        timeout_s=_budget_s(ctx, 300.0),
        Parameters=[
            {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
            {"ParameterKey": "KafkaVersion", "ParameterValue": kafka_version},
        ],
    )
    cluster_info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    assert cluster_info["State"] == "ACTIVE", (
        f"cluster is {cluster_info['State']!r} after the Topic resource was removed from the stack"
    )
    _wait_topic_gone(ctx, kafka, cluster_arn, topic_name, timeout_s=_budget_s(ctx, 120.0))
    remaining_topics = _topics(kafka, cluster_arn, topic_name)
    assert remaining_topics == [], (
        f"ListTopics still lists {remaining_topics!r} after DescribeTopic reports the topic gone"
    )

    delete_stack(cfn, stack_id, timeout_s=_budget_s(ctx, _DELETE_BUDGET_S), ctx=ctx)

    remaining_clusters = _clusters(kafka, cluster_name)
    assert remaining_clusters == [], (
        f"ListClustersV2 still lists {remaining_clusters!r} after the delete"
    )
    expect_error(lambda: kafka.describe_cluster_v2(ClusterArn=cluster_arn), *_CLUSTER_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
