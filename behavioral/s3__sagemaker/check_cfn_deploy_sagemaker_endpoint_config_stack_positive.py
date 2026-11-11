"""cfn-deploy-sagemaker-endpoint-config-stack-positive."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-endpoint-config-stack-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RoleName:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  ExecRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-scoped-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub '${DataBucket.Arn}/*'
        - PolicyName: logs-and-ecr
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - ecr:GetAuthorizationToken
                  - ecr:BatchCheckLayerAvailability
                  - ecr:GetDownloadUrlForLayer
                  - ecr:BatchGetImage
                Resource: '*'
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleArn:
    Value: !GetAtt ExecRole.Arn
"""

# Well-known first-party built-in-algorithm ECR registry account IDs per region (linear-learner
# and siblings share the same per-region account since they were published from the same build).
_LINEAR_LEARNER_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "sa-east-1": "855470959533",
}


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
    """Model + EndpointConfig + Endpoint, wired to a training job's S3-backed model artifact,
    actually serve real-time inference (not merely reach InService)."""
    run_start = time.time()
    image = _linear_learner_image(ctx.region)
    role_name = _xname(ctx, "epsrole")
    result = _deploy_cfn(
        ctx, _TEMPLATE, parameters={"RoleName": role_name}, timeout_s=180.0
    )
    bucket = result["outputs"]["BucketName"]
    role_arn = result["outputs"]["RoleArn"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_tiny_binary_csv())
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sm = ctx.client("sagemaker")
    job_name = _xname(ctx, "epstrain")
    sm.create_training_job(
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        Tags=_xsvc_tags_kv(),
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/train/",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 5,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "predictor_type": "binary_classifier",
            "feature_dim": "2",
            "mini_batch_size": "8",
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_training_job(ctx, job_name))
    train_status = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"],
        lambda s: s in {"Completed", "Failed", "Stopped"},
        timeout_s=_budget_s(ctx, 900.0),
        interval_s=2.0,
        description=f"training job {job_name}",
        ctx=ctx,
    )
    assert train_status == "Completed", train_status
    artifact_uri = sm.describe_training_job(TrainingJobName=job_name)["ModelArtifacts"][
        "S3ModelArtifacts"
    ]
    assert artifact_uri.startswith(f"s3://{bucket}/"), (
        f"expected model artifacts under s3://{bucket}/, got {artifact_uri!r}"
    )

    model_name = _xname(ctx, "epsmodel")
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": image, "ModelDataUrl": artifact_uri},
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: sm.delete_model(ModelName=model_name)))

    config_name = _xname(ctx, "epsconfig")
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
                "InitialVariantWeight": 1.0,
            }
        ],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: sm.delete_endpoint_config(EndpointConfigName=config_name)
        )
    )

    endpoint_name = _xname(ctx, "epsendpoint")
    sm.create_endpoint(
        EndpointName=endpoint_name, EndpointConfigName=config_name, Tags=_xsvc_tags_kv()
    )
    ctx.on_cleanup(lambda: _safe_delete_endpoint(ctx, endpoint_name))
    ctx.on_cleanup(lambda: _cleanup_endpoint_lineage(ctx, endpoint_name, run_start))

    ep_status = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"],
        lambda s: s in {"InService", "Failed"},
        timeout_s=_budget_s(ctx, 900.0),
        interval_s=2.0,
        description=f"endpoint {endpoint_name} InService",
        ctx=ctx,
    )
    assert ep_status == "InService", sm.describe_endpoint(
        EndpointName=endpoint_name
    ).get("FailureReason")

    runtime = ctx.client("sagemaker-runtime")
    resp = runtime.invoke_endpoint(
        EndpointName=endpoint_name,
        ContentType="text/csv",
        Accept="application/json",
        Body=b"0.1,0.2",
    )
    payload = json.loads(resp["Body"].read())
    assert "predictions" in payload, payload
    assert len(payload["predictions"]) == 1, (
        f"expected exactly 1 prediction for 1 input row, got {len(payload['predictions'])}: {payload}"
    )
    assert "score" in payload["predictions"][0], (
        f"expected a 'score' field in the prediction, got keys "
        f"{sorted(payload['predictions'][0])}"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_ACCOUNT_BY_REGION.get(region)
    if not account:
        raise AssertionError(
            f"no hardcoded linear-learner built-in-algorithm ECR account for region {region!r}"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _tiny_binary_csv() -> bytes:
    rows = []
    for i in range(20):
        label = i % 2
        f1 = 0.1 + 0.01 * i if label else 0.9 - 0.01 * i
        f2 = 0.2 + 0.01 * i if label else 0.8 - 0.01 * i
        rows.append(f"{label},{f1:.3f},{f2:.3f}")
    return ("\n".join(rows) + "\n").encode("utf-8")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    to_delete = []
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            to_delete.append({"Key": obj["Key"]})
    for i in range(0, len(to_delete), 1000):
        chunk = to_delete[i : i + 1000]
        if chunk:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": chunk})


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _safe_delete_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise
        _poll_until(
            lambda: sm.describe_training_job(TrainingJobName=job_name)[
                "TrainingJobStatus"
            ],
            lambda s: s in {"Completed", "Failed", "Stopped"},
            # Stopping -> Stopped can take minutes; 600 s plus the endpoint (300 s) and stack
            # (120 s) teardown waits fits the 1200 s cleanup budget.
            timeout_s=600.0,
            interval_s=5.0,
            description=f"stop training job {job_name}",
        )
    # SageMaker auto-creates an experiment trial component to track the training job; DeleteTrainingJob
    # does not remove it, so it must be deleted directly, matched by its SourceArn.
    job_arn = desc.get("TrainingJobArn")
    if job_arn:
        for tc in sm.list_trial_components(SourceArn=job_arn).get(
            "TrialComponentSummaries", []
        ):
            _safe_delete(
                lambda name=tc["TrialComponentName"]: sm.delete_trial_component(
                    TrialComponentName=name
                )
            )
    # DeleteTrainingJob only accepts a terminal job with no active warm pool; this check never
    # opts into managed warm pools, so a terminal status here is always eligible.
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _cleanup_endpoint_lineage(ctx, endpoint_name: str, created_after: float) -> None:
    """DeleteEndpoint does not remove the Action/Context SageMaker auto-creates to track the
    deployment in its lineage graph; they must be looked up and deleted directly while the
    endpoint (their source) still exists. The Action's SourceUri is the endpoint ARN, but the
    matching Context is not reliably found the same way, so it is matched by name instead —
    every lineage entity this check causes is named from `endpoint_name`, which carries this
    check's own unique-name prefix and cannot collide with another check's resources."""
    sm = ctx.client("sagemaker")
    try:
        endpoint_arn = sm.describe_endpoint(EndpointName=endpoint_name)["EndpointArn"]
    except ClientError as exc:
        if not _gone(exc):
            raise
        endpoint_arn = None
    if endpoint_arn:
        for action in sm.list_actions(SourceUri=endpoint_arn).get(
            "ActionSummaries", []
        ):
            _delete_lineage_entity(
                sm,
                action["ActionArn"],
                lambda name=action["ActionName"]: sm.delete_action(ActionName=name),
            )
    since = datetime.fromtimestamp(created_after, tz=timezone.utc)
    for context in sm.list_contexts(CreatedAfter=since).get("ContextSummaries", []):
        if context["ContextName"].startswith(endpoint_name):
            _delete_lineage_entity(
                sm,
                context["ContextArn"],
                lambda name=context["ContextName"]: sm.delete_context(ContextName=name),
            )


def _delete_lineage_entity(sm, arn: str, delete) -> None:
    """Teardown: drop the entity's lineage associations, then the entity (refused until then)."""
    for key in ("SourceArn", "DestinationArn"):
        for page in sm.get_paginator("list_associations").paginate(**{key: arn}):
            for assoc in page.get("AssociationSummaries", []):
                _safe_delete(
                    lambda a=assoc: sm.delete_association(
                        SourceArn=a["SourceArn"], DestinationArn=a["DestinationArn"]
                    )
                )
    _safe_delete(delete)


def _safe_delete(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not _gone(exc):
            raise


def _safe_delete_endpoint(ctx, endpoint_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_endpoint(EndpointName=endpoint_name)
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    _poll_until(
        lambda: _endpoint_exists(sm, endpoint_name),
        lambda exists: not exists,
        timeout_s=300.0,
        interval_s=10.0,
        description=f"delete endpoint {endpoint_name}",
    )


def _endpoint_exists(sm, endpoint_name: str) -> bool:
    try:
        sm.describe_endpoint(EndpointName=endpoint_name)
        return True
    except ClientError as exc:
        if not _gone(exc):
            raise
        return False


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not _gone(exc):
                raise
            return "GONE"

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
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=1.0,
        description=f"CFN stack {name}",
        ctx=ctx,
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
