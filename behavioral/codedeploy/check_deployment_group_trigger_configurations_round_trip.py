"""deployment-group-trigger-configurations-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deployment-group-trigger-configurations-round-trip"
GROUP = "representation"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Complex triggerConfigurations supplied at CreateDeploymentGroup, including nested
    event-type lists, are returned unchanged by GetDeploymentGroup."""
    cd = ctx.client("codedeploy")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-cdtopic-a-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    topic_arn_2 = sns.create_topic(Name=ctx.unique_name("sim2real-cdtopic-b-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn_2))

    role_arn = _create_service_role(ctx)

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    dg_name = ctx.unique_name("sim2real-cddg-")
    # CodeDeploy rejects duplicate trigger target ARNs across trigger configurations
    # (InvalidTriggerConfigException: "Duplicate Trigger target arn detected"), so each
    # trigger must target a distinct SNS topic.
    trigger_configurations = [
        {
            "triggerName": "on-start-and-success",
            "triggerTargetArn": topic_arn,
            "triggerEvents": ["DeploymentStart", "DeploymentSuccess"],
        },
        {
            "triggerName": "on-failure-and-stop",
            "triggerTargetArn": topic_arn_2,
            "triggerEvents": ["DeploymentFailure", "DeploymentStop", "DeploymentRollback"],
        },
    ]
    _create_deployment_group_with_role_retry(
        ctx,
        cd,
        applicationName=app_name,
        deploymentGroupName=dg_name,
        serviceRoleArn=role_arn,
        triggerConfigurations=trigger_configurations,
    )

    resp = cd.get_deployment_group(applicationName=app_name, deploymentGroupName=dg_name)
    got = resp["deploymentGroupInfo"]["triggerConfigurations"]

    def _normalize(configs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            (
                {
                    "triggerName": c["triggerName"],
                    "triggerTargetArn": c["triggerTargetArn"],
                    "triggerEvents": sorted(c["triggerEvents"]),
                }
                for c in configs
            ),
            key=lambda c: c["triggerName"],
        )

    expected = _normalize(trigger_configurations)
    actual = _normalize(got)
    assert actual == expected, (
        f"GetDeploymentGroup triggerConfigurations mismatch: expected {expected!r}, got {actual!r}"
    )


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cdrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codedeploy.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_deployment_group_with_role_retry(ctx, cd, **kwargs):
    """IAM role propagation to CodeDeploy is eventually consistent -- retry on
    InvalidRoleException for a bounded window."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return cd.create_deployment_group(**kwargs)
        except cd.exceptions.InvalidRoleException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
