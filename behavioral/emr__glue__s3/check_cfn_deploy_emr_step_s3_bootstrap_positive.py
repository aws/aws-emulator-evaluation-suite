"""cfn-deploy-emr-step-s3-bootstrap-positive."""

from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cfn-deploy-emr-step-s3-bootstrap-positive"
GROUP = "deployment-order"
SERVICES = ["emr", "glue", "s3"]

_MARKER = "sim2real-bootstrap-ran-ok"


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-deployed EMR cluster's bootstrap action, sourced from an S3 object, actually
    executes on the node: its stdout (echoed marker text) shows up in the S3-delivered
    bootstrap-action logs under the cluster's LogUri prefix."""
    s3 = ctx.client("s3")
    script_bucket = _xname(ctx, "emrboot-scripts")
    region = s3.meta.region_name
    if region and region != "us-east-1":
        s3.create_bucket(
            Bucket=script_bucket,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    else:
        s3.create_bucket(Bucket=script_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, script_bucket))
    script_key = "scripts/bootstrap.sh"
    script_body = f'#!/bin/bash\necho "{_MARKER}"\n'
    s3.put_object(Bucket=script_bucket, Key=script_key, Body=script_body.encode())
    s3.put_bucket_tagging(Bucket=script_bucket, Tagging={"TagSet": _xsvc_tags_kv()})

    cluster_name = _xname(ctx, "emrboot")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ScriptBucketName": {"Type": "String"},
                "ScriptKey": {"Type": "String"},
            },
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
                        "BootstrapActions": [
                            {
                                "Name": "s3-sourced-bootstrap",
                                "ScriptBootstrapAction": {
                                    "Path": {
                                        "Fn::Sub": "s3://${ScriptBucketName}/${ScriptKey}"
                                    }
                                },
                            }
                        ],
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

    result = _deploy_cfn(
        ctx,
        template,
        parameters={"ScriptBucketName": script_bucket, "ScriptKey": script_key},
        timeout_s=900,
    )
    cluster_id = result["outputs"]["ClusterId"]
    log_bucket = result["outputs"]["LogBucketName"]
    ctx.on_cleanup(
        lambda: _empty_and_delete_bucket(ctx, log_bucket, delete_bucket=False)
    )

    s3 = ctx.client("s3")

    def _find_bootstrap_stdout():
        prefix = f"logs/{cluster_id}/node/"
        keys: list[str] = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=log_bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                if "bootstrap-actions" in obj["Key"] and "stdout" in obj["Key"]:
                    keys.append(obj["Key"])
        return keys

    stdout_keys = _poll_until(
        _find_bootstrap_stdout,
        lambda keys: len(keys) > 0,
        timeout_s=900.0,
        interval_s=15.0,
        description="EMR bootstrap-action stdout log delivered to S3",
    )
    assert len(stdout_keys) > 0, (
        f"no bootstrap-action stdout log delivered under logs/{cluster_id}/node/ in {log_bucket}"
    )

    found_marker = False
    for key in stdout_keys:
        body = s3.get_object(Bucket=log_bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        if _MARKER in body.decode(errors="replace"):
            found_marker = True
            break
    assert found_marker, (
        f"marker {_MARKER!r} not found in bootstrap stdout logs {stdout_keys}"
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


def _empty_and_delete_bucket(ctx, bucket: str, delete_bucket: bool = True) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    if delete_bucket:
        s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
