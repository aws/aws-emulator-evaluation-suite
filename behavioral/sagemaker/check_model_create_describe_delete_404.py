"""model-create-describe-delete-404."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-create-describe-delete-404"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account (AWS grants pull access to any customer account/role), so
# they let CreateModel's real "can this role actually pull this image" check succeed without
# us owning a private ECR repo of our own.
_BUILTIN_ALGO_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


def _error(fn):
    """Call fn(); return the (code, HTTP status, message) of its ClientError. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Model transitions created -> describable -> listed -> deleted, then Describe is refused,
    the filtered listing drops it, and a second DeleteModel on the dead name is refused too.
    The knn image registry map is the built-in-algorithm image prerequisite, not this check's claim."""
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real, pullable inference image"
        )

    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-model-")

    role_arn = _create_sagemaker_execution_role(ctx, iam)

    create_resp = _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={
                "Image": f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1",
            },
            Tags=[{"Key": "sim2real-owner", "Value": "sagemaker-behavioral-suite"}],
        )
    )
    ctx.on_cleanup(lambda: _delete_model_quiet(sm, name))
    assert create_resp["ModelArn"].endswith(f"model/{name}"), (
        f"expected ModelArn to end with model/{name}, got {create_resp['ModelArn']!r}"
    )

    described = sm.describe_model(ModelName=name)
    assert described["ModelName"] == name, f"expected ModelName {name!r}, got {described['ModelName']!r}"
    assert described["ModelArn"] == create_resp["ModelArn"], (
        f"expected ModelArn {create_resp['ModelArn']!r}, got {described['ModelArn']!r}"
    )

    listed = _list_model_names(sm, name)
    assert name in listed, f"expected list_models(NameContains=name) to hold the model before the delete, got {sorted(listed)!r}"

    sm.delete_model(ModelName=name)

    code, status, message = _error(lambda: sm.describe_model(ModelName=name))
    assert code == "ValidationException", f"expected ValidationException on describe of deleted model, got {code!r}"
    assert status == 400, f"expected HTTP 400 on describe of deleted model, got {status!r}"
    expected_message = f'Could not find model "{name}".'
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    listed_after = _list_model_names(sm, name)
    assert name not in listed_after, (
        f"expected list_models(NameContains=name) to no longer hold the deleted model, got {sorted(listed_after)!r}"
    )

    second_code, second_status, second_message = _error(lambda: sm.delete_model(ModelName=name))
    assert second_code == "ValidationException", (
        f"expected a second DeleteModel on an already-deleted model to fail with "
        f"ValidationException too, got {second_code!r}"
    )
    assert second_status == 400, f"expected HTTP 400 on the second DeleteModel, got {second_status!r}"
    expected_message = f'Could not find model "{name}".'
    assert second_message == expected_message, f"expected the message {expected_message!r}, got {second_message!r}"


def _list_model_names(sm, name: str) -> set:
    """Every ModelName list_models returns for NameContains=name, across all pages."""
    names = set()
    for page in sm.get_paginator("list_models").paginate(NameContains=name):
        names.update(m["ModelName"] for m in page["Models"])
    return names


def _create_sagemaker_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-owner", "Value": "sagemaker-behavioral-suite"}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """IAM roles are eventually consistent; poll the role-dependent call until IAM's
    propagation window closes instead of trusting a fixed sleep to outlast it."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            message = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _delete_model_quiet(sm, name: str) -> None:
    try:
        sm.delete_model(ModelName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

