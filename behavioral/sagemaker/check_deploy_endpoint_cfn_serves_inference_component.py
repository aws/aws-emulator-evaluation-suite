"""deploy-endpoint-cfn-serves-inference-component."""
from __future__ import annotations

import io
import json
import tarfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-endpoint-cfn-serves-inference-component"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# A publicly pullable AWS Deep Learning Container that honours SAGEMAKER_BIND_TO_PORT, which an
# inference component's container must; the built-in XGBoost image listens on 8080 only, so its
# component fails the health check. CreateModel verifies the role can pull the image, so a
# fabricated URI does not work.
_IMAGE_REPO = "763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Model, EndpointConfig and Endpoint created by a CloudFormation stack reach CREATE_COMPLETE and an
    InService endpoint that accepts CreateInferenceComponent for the stack's model; the component reaches
    InService and describes with the stack's endpoint and model names.
    """
    image_uri = _IMAGE_REPO.format(region=ctx.region)
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, s3)
    model_data_url = _stage_sample_model_artifact(ctx, s3, bucket)

    stack_name = ctx.unique_name("sim2real-cfn-ic-")
    role_name = ctx.unique_name("sim2real-cfn-ic-role-")
    model_name = ctx.unique_name("sim2real-cfn-ic-model-")
    epc_name = ctx.unique_name("sim2real-cfn-ic-epc-")
    ep_name = ctx.unique_name("sim2real-cfn-ic-ep-")
    variant_name = "AllTraffic"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sagemaker.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
                        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
                    ],
                },
            },
            "IcModel": {
                "Type": "AWS::SageMaker::Model",
                "Properties": {
                    "ModelName": model_name,
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Containers": [
                        {
                            "Image": image_uri,
                            "ModelDataUrl": model_data_url,
                        }
                    ],
                },
            },
            "IcEndpointConfig": {
                "Type": "AWS::SageMaker::EndpointConfig",
                "Properties": {
                    "EndpointConfigName": epc_name,
                    # An endpoint config with a model-less ProductionVariant (no ModelName --
                    # required so InferenceComponents can be attached later) must carry its own
                    # ExecutionRoleArn; real AWS rejects the config at create time otherwise
                    # ("does not include a required specification for endpoints with Inference
                    # Components enabled").
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "ProductionVariants": [
                        {
                            "VariantName": variant_name,
                            "InstanceType": "ml.m5.xlarge",
                            "InitialInstanceCount": 1,
                        }
                    ],
                },
            },
            "IcEndpoint": {
                "Type": "AWS::SageMaker::Endpoint",
                "Properties": {
                    "EndpointName": ep_name,
                    "EndpointConfigName": {"Fn::GetAtt": ["IcEndpointConfig", "EndpointConfigName"]},
                },
            },
        },
        "Outputs": {
            "DeployedEndpointName": {"Value": {"Fn::GetAtt": ["IcEndpoint", "EndpointName"]}},
            "DeployedModelName": {"Value": {"Fn::GetAtt": ["IcModel", "ModelName"]}},
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"].endswith(("_COMPLETE", "_FAILED")),
        timeout_s=900,
        interval_s=15,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack did not reach CREATE_COMPLETE: expected CREATE_COMPLETE, "
        f"got {stack['StackStatus']} ({stack.get('StackStatusReason')}); "
        f"failed resources: {_failed_resource_reasons(cfn, stack_name)}"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    deployed_endpoint = outputs["DeployedEndpointName"]
    deployed_model = outputs["DeployedModelName"]
    assert deployed_endpoint == ep_name, (
        f"stack output DeployedEndpointName mismatch: expected {ep_name!r}, "
        f"got {deployed_endpoint!r}"
    )
    assert deployed_model == model_name, (
        f"stack output DeployedModelName mismatch: expected {model_name!r}, "
        f"got {deployed_model!r}"
    )

    # CloudFormation's AWS::SageMaker::Endpoint resource only reports CREATE_COMPLETE
    # once the underlying Endpoint is InService, but assert it explicitly rather than
    # trusting the stack-level status alone.
    ep_desc = sm.describe_endpoint(EndpointName=deployed_endpoint)
    assert ep_desc["EndpointStatus"] == "InService", (
        f"CFN-deployed endpoint {deployed_endpoint!r} not InService: "
        f"expected InService, got {ep_desc['EndpointStatus']!r}"
    )

    # The real behavioral assertion: the CFN-deployed Endpoint must actually accept a
    # data-plane CreateInferenceComponent attachment referencing the CFN-deployed Model,
    # and that attachment must itself reach InService -- accepting the create call is not
    # enough, because a target could echo the request back without ever actually deploying it.
    ic_name = ctx.unique_name("sim2real-cfn-ic-comp-")
    sm.create_inference_component(
        InferenceComponentName=ic_name,
        EndpointName=deployed_endpoint,
        VariantName=variant_name,
        RuntimeConfig={"CopyCount": 1},
        Specification={
            "ModelName": deployed_model,
            "ComputeResourceRequirements": {
                "MinMemoryRequiredInMb": 4096,
                "NumberOfCpuCoresRequired": 2,
            },
        },
    )
    ctx.on_cleanup(lambda: _delete_ic_quiet(sm, ic_name))

    ic_desc = _poll_until(
        lambda: sm.describe_inference_component(InferenceComponentName=ic_name),
        lambda d: d["InferenceComponentStatus"] not in ("Creating", "Updating"),
        timeout_s=900,
        interval_s=15,
    )
    assert ic_desc["InferenceComponentStatus"] == "InService", (
        f"inference component {ic_name!r} on CFN-deployed endpoint {deployed_endpoint!r} "
        f"did not reach InService; container logs: {_tail_ic_logs(ctx, ic_name)}; "
        f"expected InService, got {ic_desc['InferenceComponentStatus']!r} "
        f"({ic_desc.get('FailureReason')})"
    )
    assert ic_desc["InferenceComponentName"] == ic_name, (
        f"describe_inference_component name mismatch: expected {ic_name!r}, "
        f"got {ic_desc['InferenceComponentName']!r}"
    )
    assert ic_desc["EndpointName"] == deployed_endpoint, (
        f"describe_inference_component endpoint mismatch: expected {deployed_endpoint!r}, "
        f"got {ic_desc['EndpointName']!r}"
    )
    assert ic_desc["Specification"]["ModelName"] == deployed_model, (
        f"describe_inference_component model mismatch: expected {deployed_model!r}, "
        f"got {ic_desc['Specification']['ModelName']!r}"
    )


def _tail_ic_logs(ctx: Any, ic_name: str) -> str:
    logs = ctx.client("logs")
    group = f"/aws/sagemaker/InferenceComponents/{ic_name}"
    try:
        streams = logs.describe_log_streams(
            logGroupName=group, orderBy="LastEventTime", descending=True, limit=5
        )["logStreams"]
    except ClientError as exc:
        return f"could not read {group}: {exc}"
    if not streams:
        return f"no log streams found in {group}"
    events = logs.get_log_events(
        logGroupName=group, logStreamName=streams[0]["logStreamName"], limit=300, startFromHead=False
    )["events"]
    lines = [e["message"] for e in events]
    return "\n".join(lines[-150:]) if lines else f"no log events found in {group}"


def _create_bucket(ctx: Any, s3) -> str:
    # AmazonSageMakerFullAccess only grants S3 access to buckets whose name contains
    # "sagemaker" -- without it, CreateModel's model-data access check fails even though
    # the role has the managed policy attached.
    bucket = ctx.unique_name("sim2real-cfn-ic-sagemaker-model-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        finally:
            s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _stage_sample_model_artifact(ctx: Any, s3, bucket: str) -> str:
    """An empty gzip'd tar: the component needs a real artifact object to download, not a model."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    dst_key = "model/model.tar.gz"
    s3.put_object(Bucket=bucket, Key=dst_key, Body=buf.getvalue())
    return f"s3://{bucket}/{dst_key}"


def _failed_resource_reasons(cfn, stack_name: str) -> list[str]:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason')}"
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _delete_ic_quiet(sm, ic_name: str) -> None:
    try:
        sm.delete_inference_component(InferenceComponentName=ic_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationException":
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            sm.describe_inference_component(InferenceComponentName=ic_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            return
        time.sleep(5)
    raise AssertionError(f"inference component {ic_name} still present 600s after delete")


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 900
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        last = stacks[0]["StackStatus"]
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED: {stacks[0].get('StackStatusReason')}")
        time.sleep(15)
    raise AssertionError(f"stack {stack_name} not deleted within 900s (last {last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
