"""cfn-alb-access-logs-to-s3-create-complete-and-listener-created."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-alb-access-logs-to-s3-create-complete-and-listener-created"
GROUP = "deploy"
SERVICES = ["cloudformation", "elbv2", "s3"]

_LOG_DELIVERY_PRINCIPAL = "logdelivery.elasticloadbalancing.amazonaws.com"
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
    }
)
_DELETE_BUDGET_S = 600.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_stack(ctx, cfn, stack_id, terminal=_TERMINAL, timeout_s=600.0):
    """Poll DescribeStacks by StackId every 5 s until a status in ``terminal``; return it."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(5)


def _empty_bucket(s3, bucket: str) -> None:
    """Empty the stack's log bucket (the delivered access-log test file) so its delete converges."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) != (
            "NoSuchBucket",
            "The specified bucket does not exist",
        ):
            raise


def _delete_stack(ctx, cfn, s3, stack_id: str, bucket: str) -> None:
    """Empty the log bucket, delete the stack by StackId, and raise unless DELETE_COMPLETE."""
    _empty_bucket(s3, bucket)
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        _wait_stack(ctx, cfn, stack_id, _TERMINAL, _DELETE_BUDGET_S)
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
    if status == "DELETE_COMPLETE":
        return
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for page in pages
        for e in page["StackEvents"]
        if e["ResourceStatus"] == "DELETE_FAILED"
    ]
    raise AssertionError(f"stack {stack_id} did not reach DELETE_COMPLETE: {failed!r}")


def _test_file_keys(s3, bucket: str, key: str) -> list:
    """Keys equal to ``key`` in ``bucket`` (the access-log test file AWS writes on enable)."""
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=key)
    return [o["Key"] for page in pages for o in page.get("Contents", []) if o["Key"] == key]


def _template() -> str:
    """A log bucket with the ELB log-delivery grant, and an internet-facing ALB whose
    LoadBalancerAttributes turn access logging on to that bucket with an empty prefix."""
    return json.dumps(
        {
            "Parameters": {
                "Token": {"Type": "String"},
                "VpcId": {"Type": "AWS::EC2::VPC::Id"},
                "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            },
            "Resources": {
                "LogsBucket": {
                    "Type": "AWS::S3::Bucket",
                    "DeletionPolicy": "Delete",
                    "UpdateReplacePolicy": "Delete",
                    "Properties": {
                        "BucketName": {"Fn::Sub": "${Token}-logs"},
                    },
                },
                "LogsBucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "LogsBucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AlbAccessLogDelivery",
                                    "Effect": "Allow",
                                    "Principal": {"Service": _LOG_DELIVERY_PRINCIPAL},
                                    "Action": "s3:PutObject",
                                    "Resource": {
                                        "Fn::Sub": "${LogsBucket.Arn}/AWSLogs/${AWS::AccountId}/*"
                                    },
                                }
                            ],
                        },
                    },
                },
                "AlbSg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": CHECK,
                        "VpcId": {"Ref": "VpcId"},
                    },
                },
                "Alb": {
                    "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    "DependsOn": "LogsBucketPolicy",
                    "Properties": {
                        "Name": {"Ref": "Token"},
                        "Type": "application",
                        "Scheme": "internet-facing",
                        "Subnets": {"Ref": "SubnetIds"},
                        "SecurityGroups": [{"Fn::GetAtt": ["AlbSg", "GroupId"]}],
                        "LoadBalancerAttributes": [
                            {"Key": "access_logs.s3.enabled", "Value": "true"},
                            {"Key": "access_logs.s3.bucket", "Value": {"Ref": "LogsBucket"}},
                            {"Key": "access_logs.s3.prefix", "Value": ""},
                        ],
                    },
                },
            },
            "Outputs": {
                "AlbArn": {"Value": {"Ref": "Alb"}},
                "BucketName": {"Value": {"Ref": "LogsBucket"}},
            },
        }
    )


def _attrs(elb, arn: str) -> dict:
    return {
        a["Key"]: a["Value"]
        for a in elb.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]
    }


def _drop_listener(elb, arn: str) -> None:
    try:
        elb.delete_listener(ListenerArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ListenerNotFound":
            raise


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation internet-facing ALB enabling access_logs.s3 to a {Ref} bucket reaches
    CREATE_COMPLETE, AWS delivers AWSLogs/<account>/ELBAccessLogTestFile to the bucket, the
    attributes read back, and a listener created on the ALB is its only listener.
    """
    cfn, elb, s3 = ctx.client("cloudformation"), ctx.client("elbv2"), ctx.client("s3")
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    assert len(subnet_ids) >= 2, f"the network's subnets cover {sorted(net.subnets)!r}, need 2 AZs"

    tok = ctx.unique_name("sim2real-alb-")
    stack_name = ctx.unique_name("sim2real-cf-albaccesslog-")
    bucket = f"{tok}-logs"
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
        Parameters=[
            {"ParameterKey": "Token", "ParameterValue": tok},
            {"ParameterKey": "VpcId", "ParameterValue": net.vpc_id},
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
        ],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, s3, stack_id, bucket))
    status = _wait_stack(ctx, cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"the stack reached {status!r}, not CREATE_COMPLETE"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }
    arn = outputs["AlbArn"]
    assert outputs["BucketName"] == bucket, f"BucketName output {outputs['BucketName']!r}"

    described = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"]
    by_arn = {lb["LoadBalancerArn"]: lb for lb in described}
    assert list(by_arn) == [arn], f"DescribeLoadBalancers for {arn!r} returned {sorted(by_arn)!r}"
    lb = by_arn[arn]
    assert (lb["Type"], lb["Scheme"]) == ("application", "internet-facing"), (
        f"DescribeLoadBalancers read Type {lb['Type']!r}, Scheme {lb['Scheme']!r}"
    )

    attrs = _attrs(elb, arn)
    got = {
        k: attrs.get(k)
        for k in ("access_logs.s3.enabled", "access_logs.s3.bucket", "access_logs.s3.prefix")
    }
    assert got == {
        "access_logs.s3.enabled": "true",
        "access_logs.s3.bucket": bucket,
        "access_logs.s3.prefix": "",
    }, f"the declared access_logs attributes read {got!r}"

    test_key = f"AWSLogs/{ctx.account}/ELBAccessLogTestFile"
    timeout_s = _budget_s(ctx, 120.0)
    deadline = time.monotonic() + timeout_s
    while _test_file_keys(s3, bucket, test_key) != [test_key]:
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("waiting for the access-log test file: the run budget ended")
            raise AssertionError(
                f"{test_key!r} not delivered to {bucket!r} within {timeout_s:.0f}s"
            )
        time.sleep(5)

    created = elb.create_listener(
        LoadBalancerArn=arn,
        Port=80,
        Protocol="HTTP",
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": "200",
                    "ContentType": "text/plain",
                    "MessageBody": "ok",
                },
            }
        ],
    )["Listeners"][0]
    listener_arn = created["ListenerArn"]
    ctx.on_cleanup(lambda: _drop_listener(elb, listener_arn))
    assert (created["LoadBalancerArn"], created["Port"], created["Protocol"]) == (
        arn,
        80,
        "HTTP",
    ), f"CreateListener answered {created!r}"

    listed = elb.describe_listeners(LoadBalancerArn=arn)["Listeners"]
    assert [l["ListenerArn"] for l in listed] == [listener_arn], (
        f"DescribeListeners after the create reads {listed!r}, expected only {listener_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
