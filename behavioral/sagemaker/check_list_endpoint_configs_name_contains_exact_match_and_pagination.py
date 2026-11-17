"""list-endpoint-configs-name-contains-exact-match-and-pagination."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-endpoint-configs-name-contains-exact-match-and-pagination"
GROUP = "listing"
SERVICES = ["sagemaker", "iam"]

_CONTAINER_IMAGE_TEMPLATE = "763104351884.dkr.ecr.{region}.amazonaws.com/pytorch-inference:1.12.1-cpu-py38"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _execution_role_trust_document() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _provision_execution_role(ctx, iam) -> str:
    """Create a role SageMaker can assume and attach the managed inference policy."""
    role_name = ctx.unique_name("sim2real-behav-sm-epc-role-")
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_execution_role_trust_document()),
    )
    arn = created["Role"]["Arn"]

    def _detach_and_delete() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_detach_and_delete)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return arn


def _create_model_once_role_is_assumable(sm, model_name: str, role_arn: str, image: str,
                                          deadline_s: float = 90.0, interval_s: float = 5.0) -> None:
    """Retry CreateModel across IAM's propagation lag for a freshly attached trust policy.

    SageMaker rejects the role with ValidationException naming this exact ARN until the
    new trust policy has propagated; no API exposes that state to poll for directly.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            sm.create_model(
                ModelName=model_name,
                ExecutionRoleArn=role_arn,
                PrimaryContainer={"Image": image, "Mode": "SingleModel"},
            )
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationException" and role_arn in err.get("Message", "") \
                    and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _production_variant(model_name: str) -> dict:
    return {
        "VariantName": "AllTraffic",
        "ModelName": model_name,
        "InitialInstanceCount": 1,
        "InstanceType": "ml.t2.medium",
        "InitialVariantWeight": 1.0,
    }


def _matching_configs(sm, name_contains: str) -> list[dict]:
    """Every EndpointConfigSummary across every page whose name contains *name_contains*."""
    matches: list[dict] = []
    paginator = sm.get_paginator("list_endpoint_configs")
    for page in paginator.paginate(NameContains=name_contains):
        matches.extend(page["EndpointConfigs"])
    return matches


def _poll_until(observe, predicate, deadline_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + deadline_s
    result = observe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = observe()
    return result


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEndpointConfigs(NameContains=...) returns exactly the matching config with its
    exact name, ARN and creation time, drops it once deleted, and MaxResults=1 walks a
    two-config result one page at a time with a NextToken on every page but the last.
    """
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")

    role_arn = _provision_execution_role(ctx, iam)
    model_name = ctx.unique_name("sim2real-behav-sm-epc-model-")
    image = _CONTAINER_IMAGE_TEMPLATE.format(region=ctx.region)
    ctx.on_cleanup(_teardown(lambda: sm.delete_model(ModelName=model_name), "ValidationException"))
    _create_model_once_role_is_assumable(sm, model_name, role_arn, image)

    # --- exact match, then drop after delete -----------------------------------------
    solo_name = ctx.unique_name("sim2real-behav-sm-epc-solo-")
    ctx.on_cleanup(_teardown(lambda: sm.delete_endpoint_config(EndpointConfigName=solo_name), "ValidationException"))
    sm.create_endpoint_config(
        EndpointConfigName=solo_name,
        ProductionVariants=[_production_variant(model_name)],
    )
    created = sm.describe_endpoint_config(EndpointConfigName=solo_name)

    found = _poll_until(
        lambda: _matching_configs(sm, solo_name),
        lambda configs: len(configs) == 1,
    )
    assert len(found) == 1, (
        f"expected exactly one EndpointConfigSummary for NameContains={solo_name!r}, "
        f"got {len(found)}: {found!r}"
    )
    summary = found[0]
    assert summary["EndpointConfigName"] == solo_name, (
        f"expected the summary's name to be {solo_name!r}, got {summary['EndpointConfigName']!r}"
    )
    assert summary["EndpointConfigArn"] == created["EndpointConfigArn"], (
        f"expected the summary's ARN to match DescribeEndpointConfig's "
        f"{created['EndpointConfigArn']!r}, got {summary['EndpointConfigArn']!r}"
    )
    assert summary["CreationTime"] == created["CreationTime"], (
        f"expected the summary's CreationTime to match DescribeEndpointConfig's "
        f"{created['CreationTime']!r}, got {summary['CreationTime']!r}"
    )

    sm.delete_endpoint_config(EndpointConfigName=solo_name)
    after_delete = _poll_until(
        lambda: _matching_configs(sm, solo_name),
        lambda configs: configs == [],
    )
    assert after_delete == [], (
        f"expected NameContains={solo_name!r} to return no configs after DeleteEndpointConfig, "
        f"got {after_delete!r}"
    )

    # --- MaxResults=1 walk over two configs -------------------------------------------
    pair_prefix = ctx.unique_name("sim2real-behav-sm-epc-pair-")
    config_a_in_pair = f"{pair_prefix}-a"
    config_b_in_pair = f"{pair_prefix}-b"
    ctx.on_cleanup(_teardown(lambda: sm.delete_endpoint_config(EndpointConfigName=config_a_in_pair), "ValidationException"))
    sm.create_endpoint_config(
        EndpointConfigName=config_a_in_pair,
        ProductionVariants=[_production_variant(model_name)],
    )
    ctx.on_cleanup(_teardown(lambda: sm.delete_endpoint_config(EndpointConfigName=config_b_in_pair), "ValidationException"))
    sm.create_endpoint_config(
        EndpointConfigName=config_b_in_pair,
        ProductionVariants=[_production_variant(model_name)],
    )
    _poll_until(
        lambda: _matching_configs(sm, pair_prefix),
        lambda configs: len(configs) == 2,
    )

    pages: list[dict] = []
    next_token = None
    for _ in range(4):
        kwargs = {"NameContains": pair_prefix, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = sm.list_endpoint_configs(**kwargs)
        pages.append(page)
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert len(pages) == 2, (
        f"expected a MaxResults=1 walk over two matching configs to take exactly 2 pages, "
        f"took {len(pages)}: {pages!r}"
    )
    for page in pages:
        assert len(page["EndpointConfigs"]) == 1, (
            f"expected each MaxResults=1 page to carry exactly one config, got "
            f"{len(page['EndpointConfigs'])}: {page['EndpointConfigs']!r}"
        )
    assert pages[0].get("NextToken"), (
        f"expected the first of two MaxResults=1 pages to carry a NextToken, got {pages[0]!r}"
    )
    assert not pages[1].get("NextToken"), (
        f"expected the second (last) MaxResults=1 page to carry no NextToken, got {pages[1]!r}"
    )
    walked_names = {pages[0]["EndpointConfigs"][0]["EndpointConfigName"],
                    pages[1]["EndpointConfigs"][0]["EndpointConfigName"]}
    assert walked_names == {config_a_in_pair, config_b_in_pair}, (
        f"expected the two pages together to cover {{{config_a_in_pair!r}, {config_b_in_pair!r}}}, "
        f"got {walked_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
