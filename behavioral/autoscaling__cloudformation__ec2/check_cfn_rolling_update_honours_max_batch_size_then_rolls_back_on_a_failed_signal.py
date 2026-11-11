"""cfn-rolling-update-honours-max-batch-size-then-rolls-back-on-a-failed-signal."""
from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rolling-update-honours-max-batch-size-then-rolls-back-on-a-failed-signal"
GROUP = "deployment-order"
SERVICES = ["autoscaling", "cloudformation", "ec2"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
TEMPLATE = DEPLOYMENTS / "asg-rolling-update-signals.yaml"

DESIRED = 3
MAX_BATCH_SIZE = 1
MIN_INSTANCES_IN_SERVICE = 1
#: The floor the group must never breach: the STRICTER of the two UpdatePolicy constraints.
EXPECTED_FLOOR = DESIRED - MAX_BATCH_SIZE

_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """An AutoScalingRollingUpdate replaces instances one batch at a time without letting the
    in-service count fall past the batch cap, and a FAILURE resource signal rolls the stack back
    to the launch template version it started from.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")

    assert TEMPLATE.is_file(), (
        f"the deploy artifact this check exists to exercise is missing from disk: {TEMPLATE}"
    )

    image_id = _latest_amazon_linux_ami(ec2)
    asg_name = _xname(ctx, "ru-asg")
    launch_template_name = _xname(ctx, "ru-lt")
    parameters = {
        "ImageId": image_id,
        "LaunchTemplateName": launch_template_name,
        "AsgName": asg_name,
        "DesiredCapacity": str(DESIRED),
        "MinInstancesInService": str(MIN_INSTANCES_IN_SERVICE),
        "MaxBatchSize": str(MAX_BATCH_SIZE),
        "Generation": "1",
        "SignalExitCode": "0",
    }

    # ---- Leg A: create. Reaching CREATE_COMPLETE proves DESIRED instances signalled. ----
    result = _deploy_cfn(ctx, TEMPLATE, parameters=parameters, timeout_s=1500.0)
    stack_name = result["stack_name"]
    outputs = _outputs(result)
    assert outputs["AsgNameOut"] == asg_name, (
        f"stack output AsgNameOut is {outputs.get('AsgNameOut')!r}, expected {asg_name!r}"
    )
    # Registered AFTER the deploy so LIFO runs it BEFORE the stack delete: a group that still
    # holds capacity must be drained before CloudFormation tries to remove its subnet.
    ctx.on_cleanup(lambda: _force_delete_asg_if_present(autoscaling, asg_name))

    generation_1 = _in_service_ids(autoscaling, asg_name)
    assert len(generation_1) == DESIRED, (
        f"the CreationPolicy required {DESIRED} signals, so the group must hold {DESIRED} "
        f"InService instances after CREATE_COMPLETE, got {len(generation_1)}: {generation_1!r}"
    )
    version_1 = _group_lt_version(autoscaling, asg_name)

    # ---- Leg B: the measured rolling update. ----
    # Bumping Generation rewrites UserData -> new launch template version -> the group's
    # LaunchTemplate property changes, which is a documented rolling-update trigger.
    samples = _update_and_sample(
        ctx,
        stack_name,
        {**parameters, "Generation": "2"},
        asg_name,
        timeout_s=2400.0,
        interval_s=10.0,
        description="the rolling update triggered by a new launch template version",
    )
    status = _stack_status(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", (
        f"the rolling update must succeed when every replacement signals SUCCESS, but the stack "
        f"ended in {status!r}: {_stack_reason(cfn, stack_name)!r}"
    )

    # Sampling adequacy, asserted BEFORE the minimum is trusted: a run too coarse to have seen
    # the held dip must fail as a named precondition, not pass on an unobserved minimum.
    min_samples = 3 * DESIRED
    assert len(samples) >= min_samples, (
        f"only {len(samples)} samples were taken across a {DESIRED}-batch rolling update; at "
        f"least {min_samples} are needed before the observed minimum in-service count means "
        f"anything. The update finished faster than expected -- widen the sampling, do not "
        f"trust this run."
    )
    in_service_counts = [len(sample) for sample in samples]
    observed_floor = min(in_service_counts)
    observed_ceiling = max(in_service_counts)

    # The floor: MinInstancesInService.
    assert observed_floor >= MIN_INSTANCES_IN_SERVICE, (
        f"MinInstancesInService={MIN_INSTANCES_IN_SERVICE} was breached: the group fell to "
        f"{observed_floor} InService instances during the update. Sampled counts: "
        f"{in_service_counts!r}"
    )
    # The batch cap, two-sided. Lower: no batch bigger than MaxBatchSize. Upper: CloudFormation
    # terminates before launching, so the count MUST dip -- a target that surges first (an
    # instance-refresh-style launch-before-terminate) never dips and fails here.
    assert observed_floor == EXPECTED_FLOOR, (
        f"MaxBatchSize={MAX_BATCH_SIZE} on a {DESIRED}-instance group means the in-service count "
        f"must dip to exactly {EXPECTED_FLOOR} while each batch is held: observed minimum "
        f"{observed_floor}. Below {EXPECTED_FLOOR} means a larger batch than MaxBatchSize "
        f"allows; {DESIRED} means nothing was ever taken out of service, i.e. the replacement "
        f"launched before the terminate, which this policy does not do. Sampled counts: "
        f"{in_service_counts!r}"
    )
    assert observed_ceiling <= DESIRED, (
        f"the group must never exceed its desired capacity of {DESIRED} during a rolling update "
        f"(this policy does not surge): observed maximum {observed_ceiling}. Sampled counts: "
        f"{in_service_counts!r}"
    )

    # The update did real work. Without this, "the count never dipped past the cap" is satisfied
    # by a target that performed no replacement at all.
    generation_2 = _in_service_ids(autoscaling, asg_name)
    assert len(generation_2) == DESIRED, (
        f"the group must return to {DESIRED} InService instances after the update, got "
        f"{len(generation_2)}: {generation_2!r}"
    )
    assert not (set(generation_1) & set(generation_2)), (
        f"a rolling update must replace EVERY instance: {sorted(set(generation_1) & set(generation_2))!r} "
        f"survived. Before={sorted(generation_1)!r}, after={sorted(generation_2)!r}"
    )
    version_2 = _group_lt_version(autoscaling, asg_name)
    assert version_2 != version_1, (
        f"the group must be pinned to the new launch template version after the update: it "
        f"still reports {version_2!r}, which is what it had before ({version_1!r})"
    )
    # Terminal read at EC2: the instances the group now claims are real running machines.
    for instance_id in generation_2:
        state = _ec2_state(ec2, instance_id)
        assert state == "running", (
            f"post-update instance {instance_id} is {state!r} in EC2, expected 'running'"
        )

    # ---- Leg C: the negative. Break exactly one thing -- the signal's verdict. ----
    _update_and_sample(
        ctx,
        stack_name,
        {**parameters, "Generation": "3", "SignalExitCode": "1"},
        asg_name,
        timeout_s=2400.0,
        interval_s=15.0,
        description="the rolling update whose replacements signal FAILURE",
    )
    failed_status = _stack_status(cfn, stack_name)
    assert failed_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"a replacement signalling FAILURE with MinSuccessfulInstancesPercent=100 must cancel "
        f"the update and roll the stack back, but the stack ended in {failed_status!r}: "
        f"{_stack_reason(cfn, stack_name)!r}. UPDATE_COMPLETE here means the FAILURE signal was "
        f"ignored."
    )

    # Effect absent, via an independent read at the group rather than the stack status: the
    # rollback really restored the pre-update launch template version.
    rolled_back_version = _poll_until(
        lambda: _group_lt_version(autoscaling, asg_name),
        lambda v: v == version_2,
        timeout_s=600.0,
        interval_s=15.0,
        description=(
            f"the rollback restored the group to launch template version {version_2}"
        ),
    )
    assert rolled_back_version == version_2, (
        f"the stack rolled back but the group is still pinned to launch template version "
        f"{rolled_back_version!r}; the pre-update version was {version_2!r}"
    )
    # ... and that version's UserData is the SUCCESS-signalling one, so the group cannot
    # relaunch an instance that would signal failure again.
    restored_user_data = _user_data(ec2, outputs["LaunchTemplateId"], rolled_back_version)
    assert "signal=0" in restored_user_data, (
        f"the restored launch template version {rolled_back_version} must carry the "
        f"SUCCESS-signalling UserData (marked 'signal=0'), but its UserData does not: "
        f"{restored_user_data[:200]!r}"
    )
    assert "signal=1" not in restored_user_data, (
        f"the restored launch template version {rolled_back_version} still carries the "
        f"FAILURE-signalling UserData (marked 'signal=1'): {restored_user_data[:200]!r}"
    )

    settled = _poll_until(
        lambda: _in_service_ids(autoscaling, asg_name),
        lambda ids: len(ids) == DESIRED,
        timeout_s=900.0,
        interval_s=15.0,
        description=f"the group settled back at {DESIRED} InService instances after the rollback",
    )
    assert len(settled) == DESIRED, (
        f"after the rollback the group must hold {DESIRED} InService instances, got "
        f"{len(settled)}: {settled!r}"
    )

    # The stack's own account of WHY it rolled back must name the signal, so this cannot pass
    # because the update failed for some unrelated reason.
    reasons = _asg_event_reasons(cfn, stack_name)
    assert any("signal" in reason.lower() for reason in reasons), (
        f"no stack event for the Auto Scaling group blames a resource signal, so the rollback "
        f"is not attributable to the FAILURE this check injected. Reasons seen: {reasons[:6]!r}"
    )


def _latest_amazon_linux_ami(ec2) -> str:
    """The newest Amazon-owned Amazon Linux 2023 x86_64 AMI in this region."""
    try:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2*-kernel-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
        )["Images"]
    except ClientError as exc:
        raise AssertionError(f"ec2:DescribeImages unavailable: {exc}") from exc
    if not images:
        raise AssertionError(
            "no Amazon Linux 2023 x86_64 AMI is available here, so a launch template cannot be "
            "given a valid ImageId"
        )
    return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]


def _in_service_ids(autoscaling, asg_name: str) -> list[str]:
    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    if not groups:
        raise AssertionError(f"auto scaling group {asg_name!r} not found")
    return sorted(
        i["InstanceId"]
        for i in groups[0]["Instances"]
        if i["LifecycleState"] == "InService"
    )


def _in_service_ids_or_none(autoscaling, asg_name: str) -> list[str] | None:
    """The InService ids, or None if the group cannot be read right now.

    Only for the sampling loop, where a single missed observation must not end the run. It
    narrows to ClientError deliberately: it never swallows an AssertionError.
    """
    try:
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
    except ClientError:
        return None
    if not groups:
        return None
    return sorted(
        i["InstanceId"]
        for i in groups[0]["Instances"]
        if i["LifecycleState"] == "InService"
    )


def _group_lt_version(autoscaling, asg_name: str) -> str:
    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    if not groups:
        raise AssertionError(f"auto scaling group {asg_name!r} not found")
    spec = groups[0].get("LaunchTemplate") or {}
    version = spec.get("Version")
    if not version:
        raise AssertionError(
            f"group {asg_name!r} reports no launch template version: {groups[0].get('LaunchTemplate')!r}"
        )
    return version


def _user_data(ec2, launch_template_id: str, version: str) -> str:
    """The decoded UserData of one launch template version, read from EC2."""
    versions = ec2.describe_launch_template_versions(
        LaunchTemplateId=launch_template_id, Versions=[str(version)]
    )["LaunchTemplateVersions"]
    if not versions:
        raise AssertionError(
            f"launch template {launch_template_id} has no version {version!r}"
        )
    encoded = versions[0]["LaunchTemplateData"].get("UserData")
    if not encoded:
        raise AssertionError(
            f"launch template {launch_template_id} version {version} carries no UserData"
        )
    return base64.b64decode(encoded).decode("utf-8", errors="replace")


def _ec2_state(ec2, instance_id: str) -> str:
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"]
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


def _stack_status(cfn, stack_name: str) -> str:
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]


def _stack_reason(cfn, stack_name: str) -> str:
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get(
        "StackStatusReason", ""
    )


def _asg_event_reasons(cfn, stack_name: str) -> list[str]:
    """Every ResourceStatusReason CloudFormation recorded for the Auto Scaling group."""
    reasons = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if event.get("LogicalResourceId") == "AutoScalingGroup":
                reason = event.get("ResourceStatusReason")
                if reason:
                    reasons.append(reason)
    return reasons


def _update_and_sample(
    ctx,
    stack_name: str,
    parameters: dict[str, str],
    asg_name: str,
    *,
    timeout_s: float,
    interval_s: float,
    description: str,
) -> list[list[str]]:
    """Start a stack update and SAMPLE the group's InService set until the stack goes terminal.

    The sampling is the point: the verdict must rest on the deployed group's observed
    behaviour DURING the update, and UPDATE_COMPLETE says nothing about whether the batches were
    ever honoured. Returns one InService-id list per sample, and RAISES on timeout.
    """
    cfn = ctx.client("cloudformation")
    autoscaling = ctx.client("autoscaling")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=TEMPLATE.read_text(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ],
    )
    samples: list[list[str]] = []
    deadline = time.monotonic() + timeout_s
    while True:
        # A momentarily unreadable group yields None rather than an exception: a missed sample is
        # not a verdict, and the sampling-adequacy assertion in the body is what catches a run
        # that missed too many. Nothing here swallows an AssertionError.
        sample = _in_service_ids_or_none(autoscaling, asg_name)
        if sample is not None:
            samples.append(sample)
        status = _stack_status(cfn, stack_name)
        if status in _UPDATE_TERMINAL:
            return samples
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not reach a terminal stack status within {timeout_s}s; last "
                f"status={status!r}, {len(samples)} samples taken, in-service counts="
                f"{[len(s) for s in samples]!r}"
            )
        time.sleep(interval_s)


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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


def _force_delete_asg_if_present(autoscaling, asg_name: str) -> None:
    """Scale an Auto Scaling group to zero and force-delete it; absent is not an error.

    Belt-and-braces teardown for the resource class that leaks money if it is left running."""
    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    if not groups:
        return
    deadline = time.monotonic() + 60
    while True:
        try:
            autoscaling.update_auto_scaling_group(
                AutoScalingGroupName=asg_name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "not found" in err.get("Message", ""):
                return
            if err.get("Code") not in ("ScalingActivityInProgress", "ResourceContention") or (
                time.monotonic() >= deadline
            ):
                raise
        time.sleep(2)
    try:
        autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "ValidationError" or "not found" not in err.get("Message", ""):
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup).

    The deadline is a parameter."""
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
        timeout_s=timeout_s,
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
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
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



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
