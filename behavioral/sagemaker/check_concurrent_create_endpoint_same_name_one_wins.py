"""concurrent-create-endpoint-same-name-one-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-endpoint-same-name-one-wins"
GROUP = "concurrency"
SERVICES = ["sagemaker"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateEndpoint calls with the identical endpoint name result in exactly
    one Creating/InService endpoint and the other request rejected, never two endpoints."""
    sm = ctx.client("sagemaker")
    teardown = {}
    role_arn = _create_sagemaker_execution_role(ctx)

    config_name = ctx.unique_name("sim2real-epc-")
    # A config with an execution role and no model hosts inference components: the endpoint needs no
    # container to pass a health check, so it reaches InService and deletes in minutes.
    _create_endpoint_config_once_role_propagates(
        sm,
        EndpointConfigName=config_name,
        ExecutionRoleArn=role_arn,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "InstanceType": "ml.c5.large",
                "InitialInstanceCount": 1,
            }
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name)))

    endpoint_name = ctx.unique_name("sim2real-ep-")

    def _create(_unused: int):
        try:
            sm.create_endpoint(
                EndpointName=endpoint_name,
                EndpointConfigName=config_name,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            return True, None
        except ClientError as exc:
            return False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_create, range(2)))

    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(sm, endpoint_name, teardown))

    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]
    assert len(successes) == 1, f"expected exactly one CreateEndpoint success, got {results}"
    assert len(failures) == 1, f"expected exactly one CreateEndpoint failure, got {results}"
    rejection_code, rejection_message = failures[0][1]
    assert rejection_code == "ValidationException", f"unexpected rejection code: {failures[0][1]}"

    endpoints = sm.list_endpoints(NameContains=endpoint_name)["Endpoints"]
    matching = [e for e in endpoints if e["EndpointName"] == endpoint_name]
    assert len(matching) == 1, f"expected exactly one endpoint named {endpoint_name}, found {len(matching)}"

    desc = sm.describe_endpoint(EndpointName=endpoint_name)
    assert desc["EndpointStatus"] in ("Creating", "InService"), desc["EndpointStatus"]
    assert desc["EndpointConfigName"] == config_name, (
        f"expected the sole endpoint to point at {config_name}, got {desc['EndpointConfigName']}"
    )
    expected = f'Cannot create already existing endpoint "{desc["EndpointArn"]}".'
    assert rejection_message == expected, f"expected rejection message {expected!r}, got {rejection_message!r}"


def _delete_endpoint_and_wait(sm, endpoint_name, teardown) -> None:
    """Delete the endpoint once DeleteEndpoint stops answering "Cannot update in-progress endpoint",
    then wait for DescribeEndpoint to answer "Could not find endpoint", every 2 s to a teardown
    deadline 1140 s out, inside the suite's 1200 s cleanup budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1140.0
    deadline = teardown["deadline"]
    deleted = False
    while True:
        try:
            if not deleted:
                sm.delete_endpoint(EndpointName=endpoint_name)
                deleted = True
            sm.describe_endpoint(EndpointName=endpoint_name)
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            if err["Code"] != "ValidationException":
                raise
            if message.startswith("Could not find endpoint"):
                return
            if not message.startswith("Cannot update in-progress endpoint"):
                raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"endpoint {endpoint_name} still present at the teardown deadline")
        time.sleep(2)


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _create_endpoint_config_once_role_propagates(sm, **kwargs) -> None:
    """A fresh role is not yet visible to CreateEndpointConfig's role check (IAM eventual
    consistency), so the role-related ValidationException is retried every 3 s for 60 s."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            sm.create_endpoint_config(**kwargs)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] != "ValidationException" or "role" not in error.get("Message", "").lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"execution role never propagated within 60s: {error['Message']}") from exc
            time.sleep(3)


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            if iam.get_role(RoleName=role_name)["Role"]["Arn"] == role_arn:
                return role_arn
        except ClientError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError(f"role {role_name} did not become visible within 30s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
