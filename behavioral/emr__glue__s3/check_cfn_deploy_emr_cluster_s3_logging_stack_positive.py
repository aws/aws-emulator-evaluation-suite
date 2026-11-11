"""cfn-deploy-emr-cluster-s3-logging-stack-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cfn-deploy-emr-cluster-s3-logging-stack-positive"
GROUP = "deployment-order"
SERVICES = ["emr", "glue", "s3"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-deployed EMR cluster with LogUri pointing at a stack-created S3 bucket actually
    delivers node/application logs into that bucket under the cluster-id prefix."""
    cluster_name = _xname(ctx, "emrlog")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LogBucket": {"Type": "AWS::S3::Bucket"},
                "EMRServiceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "elasticmapreduce.amazonaws.com"
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
                        ],
                    },
                },
                "EMREC2Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
                        ],
                    },
                },
                "EMRInstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {"Roles": [{"Ref": "EMREC2Role"}]},
                },
                "EMRCluster": {
                    "Type": "AWS::EMR::Cluster",
                    "DependsOn": ["EMRInstanceProfile", "EMRServiceRole", "LogBucket"],
                    "Properties": {
                        "Name": cluster_name,
                        "ReleaseLabel": "emr-6.15.0",
                        "Applications": [{"Name": "Hadoop"}],
                        "Instances": {
                            "MasterInstanceGroup": {
                                "InstanceCount": 1,
                                "InstanceType": "m5.xlarge",
                            },
                            "KeepJobFlowAliveWhenNoSteps": True,
                            "TerminationProtected": False,
                        },
                        "JobFlowRole": {"Ref": "EMRInstanceProfile"},
                        "ServiceRole": {"Ref": "EMRServiceRole"},
                        "LogUri": {"Fn::Sub": "s3://${LogBucket}/logs/"},
                        "VisibleToAllUsers": True,
                    },
                },
            },
            "Outputs": {
                "ClusterId": {"Value": {"Ref": "EMRCluster"}},
                "LogBucketName": {"Value": {"Ref": "LogBucket"}},
            },
        }
    )

    result = _deploy_cfn(ctx, template, timeout_s=900)
    cluster_id = result["outputs"]["ClusterId"]
    bucket = result["outputs"]["LogBucketName"]
    # Empty the bucket BEFORE the stack-delete cleanup runs (registered LIFO: this runs first).
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    emr = ctx.client("emr")
    cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    log_uri = cluster["LogUri"]
    assert bucket in log_uri and "logs" in log_uri, f"unexpected LogUri: {log_uri!r}"

    s3 = ctx.client("s3")

    def _list_log_objects():
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=f"logs/{cluster_id}/")
        return resp.get("Contents", [])

    objects = _poll_until(
        _list_log_objects,
        lambda objs: len(objs) > 0,
        timeout_s=900.0,
        interval_s=15.0,
        description=f"EMR log delivery to s3://{bucket}/logs/{cluster_id}/",
    )
    assert len(objects) > 0, (
        f"expected log objects under s3://{bucket}/logs/{cluster_id}/, got none"
    )
    assert any(o["Key"].startswith(f"logs/{cluster_id}/") for o in objects), (
        f"no delivered object keyed under logs/{cluster_id}/: {[o['Key'] for o in objects]!r}"
    )


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
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
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
    template_body = template.read_text() if isinstance(template, Path) else template
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


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
