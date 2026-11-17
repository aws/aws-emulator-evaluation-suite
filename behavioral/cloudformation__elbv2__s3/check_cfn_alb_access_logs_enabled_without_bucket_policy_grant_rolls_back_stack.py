"""cfn-alb-access-logs-enabled-without-bucket-policy-grant-rolls-back-stack."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-alb-access-logs-enabled-without-bucket-policy-grant-rolls-back-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "elbv2", "s3"]

_LOG_DELIVERY_PRINCIPAL = "logdelivery.elasticloadbalancing.amazonaws.com"
_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "GONE",
})
_DELETE_BUDGET_S = 600.0
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _stack_status(cfn, stack_name: str) -> str:
    """The stack's status, or "GONE" once AWS no longer keeps its record at all."""
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return "GONE"
        raise


def _wait_stack(cfn, stack_name: str, terminal=_TERMINAL, timeout_s: float = 600.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = _stack_status(cfn, stack_name)
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name} still {status!r} after {timeout_s:.0f}s")
        time.sleep(5)


def _empty_bucket(s3, cfn, stack_name: str) -> None:
    """Empty the stack's LogsBucket (the delivered access-log test file) so its delete converges."""
    try:
        bucket = cfn.describe_stack_resource(
            StackName=stack_name, LogicalResourceId="LogsBucket")["StackResourceDetail"][
            "PhysicalResourceId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        return
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_stack(cfn, s3, stack_name: str) -> None:
    _empty_bucket(s3, cfn, stack_name)
    if _stack_status(cfn, stack_name) == "GONE":
        return
    cfn.delete_stack(StackName=stack_name)
    status = _wait_stack(cfn, stack_name, {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"}, _DELETE_BUDGET_S)
    if status != "DELETE_FAILED":
        return
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
              if e["ResourceStatus"] == "DELETE_FAILED"]
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE: {failed!r}")


def _failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(rows) == 1, f"expected one CREATE_FAILED row for {logical_id}, got {rows!r}"
    return rows[0]


def _masked(text: str, *names: str) -> str:
    """``text`` with only the request id, the SDK attempt count and the run's own minted names
    blanked out."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def _handler_reason(reason: str, *names: str) -> tuple[str, str]:
    """``(masked message, HandlerErrorCode)`` of a registry-handler failure reason."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"], *names), m["code"]


def _template(with_policy: bool) -> str:
    """The same internet-facing ALB enabling access_logs.s3 to a fresh bucket; the bucket's
    ELB log-delivery grant is present or omitted."""
    resources = {
        "LogsBucket": {
            "Type": "AWS::S3::Bucket",
            "DeletionPolicy": "Delete",
            "UpdateReplacePolicy": "Delete",
            "Properties": {"BucketName": {"Fn::Sub": "${Token}-logs"}},
        },
        "AlbSg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {"GroupDescription": CHECK, "VpcId": {"Ref": "VpcId"}},
        },
        "Alb": {
            "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
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
    }
    if with_policy:
        resources["LogsBucketPolicy"] = {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "LogsBucket"},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AlbAccessLogDelivery",
                        "Effect": "Allow",
                        "Principal": {"Service": _LOG_DELIVERY_PRINCIPAL},
                        "Action": "s3:PutObject",
                        "Resource": {"Fn::Sub": "${LogsBucket.Arn}/AWSLogs/${AWS::AccountId}/*"},
                    }],
                },
            },
        }
        resources["Alb"]["DependsOn"] = "LogsBucketPolicy"
    return json.dumps({
        "Parameters": {
            "Token": {"Type": "String"},
            "VpcId": {"Type": "AWS::EC2::VPC::Id"},
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
        },
        "Resources": resources,
        "Outputs": {
            "AlbArn": {"Value": {"Ref": "Alb"}},
            "BucketName": {"Value": {"Ref": "LogsBucket"}},
        },
    })


def _attrs(elb, arn: str) -> dict:
    return {a["Key"]: a["Value"] for a in
            elb.describe_load_balancer_attributes(LoadBalancerArn=arn)["Attributes"]}


def _absent_error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation internet-facing ALB whose LoadBalancerAttributes enable access_logs.s3
    onto a bucket with no log-delivery grant fails and rolls back, creating no load balancer;
    the same template with the grant present deploys and the attributes round-trip.
    """
    cfn, elb, s3 = ctx.client("cloudformation"), ctx.client("elbv2"), ctx.client("s3")
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    assert len(subnet_ids) >= 2, f"the network's subnets cover {sorted(net.subnets)!r}, need 2 AZs"

    bad_tok = ctx.unique_name("sim2real-alb-")
    bad_stack = ctx.unique_name("sim2real-cf-albnogrant-")
    cfn.create_stack(
        StackName=bad_stack, TemplateBody=_template(with_policy=False),
        Tags=[{"Key": "sim2real", "Value": bad_stack}],
        Parameters=[
            {"ParameterKey": "Token", "ParameterValue": bad_tok},
            {"ParameterKey": "VpcId", "ParameterValue": net.vpc_id},
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, s3, bad_stack))
    status = _wait_stack(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"the ungranted-bucket stack reached {status!r}"

    got = _handler_reason(_failed_reason(cfn, bad_stack, "Alb"), bad_tok)
    want = ("Access Denied for bucket: <name>-logs. Please check S3bucket permission "
            "(Service: ElasticLoadBalancingV2, Status Code: 400, Request ID: <id>) "
            "(SDK Attempt Count: <n>)", "InvalidRequest")
    assert got == want, f"the Alb resource's failure reason read {got!r}, expected {want!r}"

    lb_gone = _absent_error(lambda: elb.describe_load_balancers(Names=[bad_tok]))
    assert lb_gone == ("LoadBalancerNotFound", f"Load balancers '[{bad_tok}]' not found"), (
        f"the rolled-back load balancer {bad_tok!r} must not exist, DescribeLoadBalancers raised "
        f"{lb_gone!r}")

    # Positive control: the same template, the bucket carrying the log-delivery grant.
    good_tok = ctx.unique_name("sim2real-alb-")
    good_stack = ctx.unique_name("sim2real-cf-albgrant-")
    cfn.create_stack(
        StackName=good_stack, TemplateBody=_template(with_policy=True),
        Tags=[{"Key": "sim2real", "Value": good_stack}],
        Parameters=[
            {"ParameterKey": "Token", "ParameterValue": good_tok},
            {"ParameterKey": "VpcId", "ParameterValue": net.vpc_id},
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, s3, good_stack))
    status = _wait_stack(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"the control stack reached {status!r}, not CREATE_COMPLETE"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=good_stack)["Stacks"][0]["Outputs"]}
    arn, bucket = outputs["AlbArn"], outputs["BucketName"]
    lbs = elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"]
    by_arn = {lb["LoadBalancerArn"] for lb in lbs}
    assert {arn} <= by_arn, f"the control load balancer must read back by its Ref ARN, got {by_arn!r}"
    got = _attrs(elb, arn)
    want = {"access_logs.s3.enabled": "true", "access_logs.s3.bucket": bucket,
            "access_logs.s3.prefix": ""}
    assert {k: got.get(k) for k in want} == want, (
        f"the control's declared access_logs attributes read {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
