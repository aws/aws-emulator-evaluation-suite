"""cli-script-ssm-parameter-created-by-cfn-then-used-by-ec2-launch-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-script-ssm-parameter-created-by-cfn-then-used-by-ec2-launch-positive"
GROUP = "cli_workflows"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-created SSM parameter's value is read via the CLI and used to configure a
    subsequent CLI-driven ec2 run-instances call; the launched instance actually reflects it."""
    require_tools("aws")

    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    vpc_id, subnet_id = _default_vpc_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError("no shared network VPC/subnet available in this account/region")

    stack_name = ctx.unique_name("sim2real-cfn-param-")
    param_name = ctx.unique_name("sim2real-instance-type-")
    desired_instance_type = "t3.micro"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ParamName": {"Type": "String"},
            "ParamValue": {"Type": "String"},
        },
        "Resources": {
            "TypeParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": {"Ref": "ParamName"},
                    "Type": "String",
                    "Value": {"Ref": "ParamValue"},
                },
            }
        },
    }
    tmpl_path = _write_temp_json(template)
    try:
        _run_aws(
            ctx,
            "cloudformation", "create-stack",
            "--stack-name", stack_name,
            "--template-body", f"file://{tmpl_path}",
            "--parameters",
            f"ParameterKey=ParamName,ParameterValue={param_name}",
            f"ParameterKey=ParamValue,ParameterValue={desired_instance_type}",
            timeout_s=60,
        )
    finally:
        os.unlink(tmpl_path)

    def _delete_stack():
        _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60)
        _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s in (None, "DELETE_COMPLETE"),
            timeout_s=300,
            interval_s=10,
            description=f"stack {stack_name} to reach DELETE_COMPLETE",
        )

    ctx.on_cleanup(_delete_stack)

    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=180,
        interval_s=5,
        description=f"stack {stack_name} to leave CREATE_IN_PROGRESS",
    )
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {status}"

    # CLI reads the CFN-created parameter's value.
    get_resp = _run_aws(ctx, "ssm", "get-parameter", "--name", param_name, timeout_s=30)
    param_value = get_resp["Parameter"]["Value"]
    assert param_value == desired_instance_type, (
        f"expected SSM parameter {param_name!r} to carry the CFN-supplied value "
        f"{desired_instance_type!r}, got {param_value!r}"
    )

    # AMI id lookup is a read-only lookaside, not the workflow under test.
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    tag_spec = json.dumps([
        {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "sim2real-cfn-param-ec2"}]}
    ])
    run_resp = _run_aws(
        ctx,
        "ec2", "run-instances",
        "--image-id", ami_id,
        "--instance-type", param_value,
        "--subnet-id", subnet_id,
        "--count", "1",
        "--tag-specifications", tag_spec,
        timeout_s=60,
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        _poll_until(
            lambda: _instance_state(ec2, instance_id),
            lambda s: s == "terminated",
            timeout_s=180,
            interval_s=10,
            description=f"instance {instance_id} to reach terminated",
        )

    ctx.on_cleanup(_terminate)

    # Freshly created instance IDs can lag briefly before DescribeInstances reflects them
    # (eventual consistency) — poll rather than assuming an immediate read is authoritative.
    desc = _poll_until(
        lambda: _describe_instance_safe(ec2, instance_id),
        lambda d: d is not None,
        timeout_s=60,
        interval_s=3,
        description=f"instance {instance_id} to become visible via DescribeInstances",
    )
    launched_type = desc["Reservations"][0]["Instances"][0]["InstanceType"]
    assert launched_type == desired_instance_type == param_value, (
        f"expected instance {instance_id} to launch as {desired_instance_type!r} "
        f"(the CFN-created SSM parameter's value), DescribeInstances reports {launched_type!r} "
        f"(SSM parameter read as {param_value!r})"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _write_temp_json(obj: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f)
    return path


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {description}; last observed: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


def _stack_status(cfn, stack_name):
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except Exception:
        return None
    if not stacks:
        return None
    return stacks[0]["StackStatus"]


def _default_vpc_subnet(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        return None, None
    return vpc_id, subnets[0]["SubnetId"]


def _instance_state(ec2, instance_id):
    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
    except Exception:
        return None
    reservations = desc.get("Reservations", [])
    if not reservations:
        return None
    return reservations[0]["Instances"][0]["State"]["Name"]


def _describe_instance_safe(ec2, instance_id):
    try:
        return ec2.describe_instances(InstanceIds=[instance_id])
    except Exception:
        return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
