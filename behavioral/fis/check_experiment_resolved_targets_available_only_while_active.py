"""experiment-resolved-targets-available-only-while-active."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "experiment-resolved-targets-available-only-while-active"
GROUP = "state-machine"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """ListExperimentResolvedTargets returns the concrete EC2 instance FIS resolved for a
    template's target block once the experiment is active, and raises
    ResourceNotFoundException for an experiment id that was never started."""
    fis = ctx.client("fis")
    instance = _launch_test_instance(ctx)
    role_arn = _create_fis_role(
        ctx,
        managed_policy_arns=(
            "arn:aws:iam::aws:policy/service-role/AWSFaultInjectionSimulatorEC2Access",
        ),
    )
    template_id = _create_experiment_template(
        ctx,
        role_arn,
        targets={
            "rebootTarget": {
                "resourceType": "aws:ec2:instance",
                "resourceArns": [instance["arn"]],
                "selectionMode": "ALL",
            }
        },
        actions={
            "reboot": {
                "actionId": "aws:ec2:reboot-instances",
                "targets": {"Instances": "rebootTarget"},
            }
        },
    )

    start = _start_experiment_with_retry(fis, template_id, ctx)
    experiment_id = start["experiment"]["id"]

    def status_probe() -> str:
        return fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]

    _poll_until(status_probe, lambda s: s in ("running", "completed"), timeout_s=90.0, interval_s=2.0)

    def resolved_probe() -> list[dict[str, Any]]:
        return fis.list_experiment_resolved_targets(experimentId=experiment_id).get(
            "resolvedTargets", []
        )

    resolved = _poll_until(resolved_probe, lambda targets: len(targets) > 0, timeout_s=60.0, interval_s=3.0)
    assert len(resolved) == 1, f"expected exactly one resolved target, got {resolved!r}"
    target = resolved[0]
    assert target["resourceType"] == "aws:ec2:instance", (
        f"expected resourceType 'aws:ec2:instance', got {target['resourceType']!r}: {target!r}"
    )
    assert target["targetName"] == "rebootTarget", (
        f"expected targetName 'rebootTarget', got {target['targetName']!r}: {target!r}"
    )
    assert any(instance["instance_id"] in value for value in target["targetInformation"].values()), (
        f"resolved target information does not reference launched instance: {target}"
    )

    # let the experiment reach a terminal state before checking the unknown-id case
    _poll_until(status_probe, lambda s: s in ("completed", "stopped", "failed"), timeout_s=90.0, interval_s=3.0)

    code, message = _error(
        lambda: fis.list_experiment_resolved_targets(experimentId="sim2real-fis-never-started")
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-started experiment id, got {code!r}"
    )
    assert message == "Experiment not found", (
        f"expected FIS's exact message 'Experiment not found' for a never-started experiment id, "
        f"got {message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _launch_test_instance(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")

    # The check's own VPC and subnet: the instance never needs a route out, only to exist.
    net_name = ctx.unique_name("sim2real-fis-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": net_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-fis-target-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": name}],
            }
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _terminate() -> None:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_terminate)

    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    account_id = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    return {"instance_id": instance_id, "arn": arn}


def _create_fis_role(ctx, managed_policy_arns: tuple[str, ...] = ()) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:fis:{ctx.region}:{account_id}:experiment/*"
                    },
                },
            }
        ],
    }
    import json

    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )
    return role_arn


def _create_experiment_template(
    ctx,
    role_arn: str,
    actions: dict,
    targets: dict | None = None,
    stop_conditions: list | None = None,
    description: str | None = None,
) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = {
        "clientToken": ctx.unique_name("sim2real-fis-tok-"),
        "description": description or "sim2real fis behavioral check",
        "stopConditions": stop_conditions or [{"source": "none"}],
        "actions": actions,
        "roleArn": role_arn,
        "targets": targets or {},
    }

    # newly-created IAM roles / policy attachments can take a few seconds to propagate
    last_exc: ClientError | None = None
    resp = None
    for attempt in range(10):
        try:
            resp = fis.create_experiment_template(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and attempt < 9:
                last_exc = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        assert last_exc is not None
        raise last_exc

    template_id = resp["experimentTemplate"]["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


def _start_experiment_with_retry(fis, template_id: str, ctx, timeout_s: float = 60.0):
    """StartExperiment can transiently fail with ValidationException("Unable to assume
    role ...") while a freshly-created IAM role/policy attachment is still propagating
    through STS; retry until that clears or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-start-"),
                experimentTemplateId=template_id,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in message.lower():
                last_exc = exc
                time.sleep(3)
                continue
            raise
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
