"""cdk-l2-ecs-asg-capacity-provider-managed-scaling-reaches-the-ecs-api."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-l2-ecs-asg-capacity-provider-managed-scaling-reaches-the-ecs-api"
GROUP = "deploy-cdk-l2-cluster"
SERVICES = ["cloudformation", "ecs"]


# Phase bounds: bootstrap, deploy (VPC, NAT, ASG, cluster), container-instance registration
# through the NAT, and ordered teardown.
_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_REGISTRATION_WAIT_S = 420.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = Path(__file__).parent / "deployments" / "cdk-ecs-asg-capacity"

# What ECS's own managed-scaling policy tracks.
_MANAGED_SCALING_NAMESPACE = "AWS/ECS/ManagedScaling"
_MANAGED_SCALING_METRIC = "CapacityProviderReservation"
_ECS_POLICY_NAME_FORM = (r"ECSManagedAutoScalingPolicy-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}"
                         r"-[0-9a-f]{12}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CDK L2 `enable_managed_scaling=True` reaches the ECS API, and ECS creates a target-tracking
    policy on CapacityProviderReservation that the stack never declares; the stack uses a launch
    template, and a container instance from the ASG registers ACTIVE.

    Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/asg-capacity-providers.html
    """
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    asg_client = ctx.client("autoscaling")
    cfn = ctx.client("cloudformation")

    # Missing app files are an artifact failure, asserted before anything is created.
    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys is missing from disk: expected app.py and cdk.json under "
        f"{_APP}, found {sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkecs-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"vpc": None, "cluster": None}

    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    # The app declares max_azs=2.
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, (
        f"this region reports {len(azs)} available AZs ({azs!r}); the app declares max_azs=2 "
        f"and needs two"
    )

    _bootstrap(ctx, qualifier, toolkit)

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    state["vpc"] = outputs["VpcId"]
    cluster_name = outputs["ClusterName"]
    state["cluster"] = cluster_name
    provider_name = outputs["CapacityProviderName"]
    asg_name = outputs["AsgName"]

    # ---- 1. the LaunchTemplate trap --------------------------------------------------
    resources = _stack_resources(cfn, stack)
    types = {r["ResourceType"] for r in resources}
    assert "AWS::EC2::LaunchTemplate" in types, (
        f"the deployed stack has no AWS::EC2::LaunchTemplate; its resource types are "
        f"{sorted(types)!r}. The app's cdk.json pins "
        f"'@aws-cdk/aws-autoscaling:generateLaunchTemplateInsteadOfLaunchConfig', which is what "
        f"makes aws-cdk-lib emit one"
    )
    assert "AWS::AutoScaling::LaunchConfiguration" not in types, (
        f"the deployed stack contains an AWS::AutoScaling::LaunchConfiguration, which AWS "
        f"refuses to create in any account that did not already have launch configurations; the "
        f"'generateLaunchTemplateInsteadOfLaunchConfig' context flag in the app's cdk.json is "
        f"supposed to prevent this. Resource types: {sorted(types)!r}"
    )
    # The stack declares no scaling policy of its own, so any policy found was made by ECS.
    assert "AWS::AutoScaling::ScalingPolicy" not in types, (
        f"the deployed stack declares an AWS::AutoScaling::ScalingPolicy of its own; the "
        f"keystone assertion below - that ECS created the scaling policy out of band - is only "
        f"meaningful if CDK declared none. Resource types: {sorted(types)!r}"
    )

    # ---- 2. the CDK properties reached the ECS API ---------------------------------
    described = ecs.describe_capacity_providers(
        capacityProviders=[provider_name])["capacityProviders"]
    assert len(described) == 1, (
        f"DescribeCapacityProviders for {provider_name!r} returned {len(described)} providers, "
        f"expected 1"
    )
    provider = described[0]
    assert provider["status"] == "ACTIVE", (
        f"capacity provider {provider_name!r} has status {provider['status']!r}, expected "
        f"'ACTIVE'"
    )
    asg_provider = provider["autoScalingGroupProvider"]
    assert asg_provider["autoScalingGroupArn"].endswith(f"/{asg_name}"), (
        f"capacity provider {provider_name!r} points at autoScalingGroupArn "
        f"{asg_provider['autoScalingGroupArn']!r}, which does not name the ASG the stack "
        f"reported ({asg_name!r})"
    )
    assert asg_provider["managedDraining"] == "ENABLED", (
        f"capacity provider {provider_name!r} reports managedDraining "
        f"{asg_provider['managedDraining']!r}, expected 'ENABLED' - the app pins "
        f"enable_managed_draining=True"
    )
    assert asg_provider["managedTerminationProtection"] == "DISABLED", (
        f"capacity provider {provider_name!r} reports managedTerminationProtection "
        f"{asg_provider['managedTerminationProtection']!r}, expected 'DISABLED' - the app pins "
        f"enable_managed_termination_protection=False"
    )
    managed = asg_provider["managedScaling"]
    assert managed["status"] == "ENABLED", (
        f"capacity provider {provider_name!r} reports managedScaling.status "
        f"{managed['status']!r}, expected 'ENABLED' - the app pins enable_managed_scaling=True. "
        f"Everything below depends on ECS having acted on this field, not merely stored it"
    )
    # The app leaves targetCapacityPercent unset, so the L2 default of 100 applies.
    target = managed["targetCapacity"]
    assert target == 100, (
        f"capacity provider {provider_name!r} reports managedScaling.targetCapacity "
        f"{target!r}, expected 100, the AsgCapacityProvider default"
    )

    # ---- 3. ECS created a scaling policy CDK never declared ---------------------------
    policies = asg_client.describe_policies(
        AutoScalingGroupName=asg_name)["ScalingPolicies"]
    assert len(policies) == 1, (
        f"the ASG {asg_name!r} has {len(policies)} scaling policies "
        f"({[p['PolicyName'] for p in policies]!r}); with managedScaling ENABLED and no policy "
        f"declared in the template, ECS must have created exactly one"
    )
    policy = policies[0]
    assert policy["PolicyType"] == "TargetTrackingScaling", (
        f"the scaling policy {policy['PolicyName']!r} on {asg_name!r} has PolicyType "
        f"{policy['PolicyType']!r}, expected 'TargetTrackingScaling' - ECS managed scaling is "
        f"implemented as target tracking"
    )
    # The name ECS gives the policy it creates, so the policy is ECS's rather than the template's.
    assert re.fullmatch(_ECS_POLICY_NAME_FORM, policy["PolicyName"]), (
        f"the scaling policy is named {policy['PolicyName']!r}, expected the form "
        f"{_ECS_POLICY_NAME_FORM!r} of a policy ECS managed scaling creates out of band"
    )
    namespace, metric = _tracked_metric(policy, asg_name)
    assert (namespace, metric) == (_MANAGED_SCALING_NAMESPACE, _MANAGED_SCALING_METRIC), (
        f"the ECS-created policy {policy['PolicyName']!r} tracks {namespace!r}/{metric!r}, "
        f"expected {_MANAGED_SCALING_NAMESPACE!r}/{_MANAGED_SCALING_METRIC!r} - the metric ECS "
        f"managed scaling is documented to drive capacity from"
    )

    # ---- 4. the capacity is real --------------------------------------------------------
    # Proves the ASG instance joined, so the scaling policy is attached to working capacity.
    instance_arn = _wait_for_container_instance(ecs, cluster_name)
    instances = ecs.describe_container_instances(
        cluster=cluster_name, containerInstances=[instance_arn])["containerInstances"]
    assert len(instances) == 1, (
        f"DescribeContainerInstances for {instance_arn!r} returned {len(instances)} instances, "
        f"expected 1"
    )
    container_instance = instances[0]
    assert container_instance["status"] == "ACTIVE", (
        f"container instance {instance_arn!r} has status "
        f"{container_instance['status']!r}, expected 'ACTIVE'"
    )
    # Confirm the instance at the ASG.
    groups = asg_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert len(groups) == 1, (
        f"DescribeAutoScalingGroups for {asg_name!r} returned {len(groups)} groups, expected 1"
    )
    asg_instance_ids = sorted(i["InstanceId"] for i in groups[0]["Instances"])
    ec2_instance_id = container_instance["ec2InstanceId"]
    assert asg_instance_ids == [ec2_instance_id], (
        f"the capacity provider's ASG {asg_name!r} (desired capacity 1) has members "
        f"{asg_instance_ids!r}, expected exactly the cluster's container instance "
        f"[{ec2_instance_id!r}]"
    )
    for resource_name in ("CPU", "MEMORY"):
        value = _registered_resource(container_instance, resource_name, instance_arn)
        assert value > 0, (
            f"container instance {instance_arn!r} registered {resource_name} {value!r}; a "
            f"joined instance must report positive {resource_name} capacity or nothing can be "
            f"placed on it"
        )
def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out / out.json never land in the source tree."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkecs-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error_code(fn) -> str:
    """Return the AWS error code a call raises; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"])
    raise AssertionError("call succeeded but was expected to be refused")


def _stack_resources(cfn, stack: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
        for r in page["StackResourceSummaries"]:
            # Hard-subscripted: a summary with no PhysicalResourceId is a defect to surface, not to
            # route around.
            found.append({
                "LogicalResourceId": r["LogicalResourceId"],
                "ResourceType": r["ResourceType"],
                "PhysicalResourceId": r["PhysicalResourceId"],
            })
    assert found, f"ListStackResources returned nothing for the deployed stack {stack!r}"
    return found


def _tracked_metric(policy: dict[str, Any], asg_name: str) -> tuple[str, str]:
    """The (namespace, metric name) a target-tracking policy tracks; raise if it has neither spec.

    A predefined spec reports namespace "<predefined>", which never equals the expected one.
    """
    config = policy.get("TargetTrackingConfiguration")
    assert config, (
        f"the scaling policy {policy['PolicyName']!r} on {asg_name!r} has no "
        f"TargetTrackingConfiguration; a TargetTrackingScaling policy must carry one"
    )
    customized = config.get("CustomizedMetricSpecification")
    predefined = config.get("PredefinedMetricSpecification")
    if customized:
        return str(customized["Namespace"]), str(customized["MetricName"])
    assert predefined, (
        f"the scaling policy {policy['PolicyName']!r} on {asg_name!r} carries neither a "
        f"CustomizedMetricSpecification nor a PredefinedMetricSpecification; its "
        f"TargetTrackingConfiguration keys are {sorted(config)!r}"
    )
    return "<predefined>", str(predefined["PredefinedMetricType"])


def _registered_resource(container_instance: dict[str, Any], name: str, arn: str) -> int:
    """One named registeredResources entry; raise if absent so missing CPU/MEMORY is not zero."""
    hits = [r for r in container_instance["registeredResources"] if r["name"] == name]
    assert len(hits) == 1, (
        f"container instance {arn!r} reports {len(hits)} registeredResources entries named "
        f"{name!r}; expected exactly 1. Entries: "
        f"{[r['name'] for r in container_instance['registeredResources']]!r}"
    )
    return int(hits[0]["integerValue"])


def _wait_for_container_instance(ecs, cluster_name: str) -> str:
    """Wait until exactly one ACTIVE container instance is registered; return its ARN or raise.

    The instance must boot and register through the NAT gateway; DRAINING etc. do not count.
    """
    deadline = time.monotonic() + _REGISTRATION_WAIT_S
    while True:
        arns: list[str] = []
        for page in ecs.get_paginator("list_container_instances").paginate(
                cluster=cluster_name, status="ACTIVE"):
            arns.extend(page["containerInstanceArns"])
        if len(arns) == 1:
            return arns[0]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after {_REGISTRATION_WAIT_S}s cluster {cluster_name!r} reports {len(arns)} ACTIVE "
                f"container instances ({arns!r}), expected exactly 1; the ASG capacity provider's "
                f"instance never joined the cluster, so the managed-scaling policy asserted above "
                f"is attached to capacity that does not work"
            )
        time.sleep(5.0)


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    r = subprocess.run(
        ["cdk", "bootstrap", f"aws://{acct}/{ctx.region}", "--qualifier", qualifier,
         "--toolkit-stack-name", toolkit,
         # AWS_MANAGED_KEY explicitly: an EMPTY value fires the bootstrap template's CreateNewKey
         # condition and mints a customer CMK with a 7-day irreversible deletion window.
         "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, *,
         timeout_s: float, expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    # --app overrides cdk.json's interpreter-agnostic "python3 app.py" with the interpreter that
    # actually has aws-cdk-lib importable; cdk.json keeps the plain form (and the
    # generateLaunchTemplateInsteadOfLaunchConfig context flag) so the app synthesizes standalone.
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _stack_status(ctx, stack: str) -> str | None:
    cfn = ctx.client("cloudformation")
    try:
        return str(cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"])
    except ClientError as exc:
        if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
            raise
        return None


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 400.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        # The first read after DeleteStack may still show the prior status, so only the two
        # terminal delete states end the poll.
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} is {status!r} after DeleteStack, expected DELETE_COMPLETE; the estate "
        f"it created is leaking"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _nats_in_vpc(ec2, vpc_id: str) -> list[dict[str, Any]]:
    """Every NAT gateway in the VPC not yet deleted or failed.

    Deleted/failed gateways stay listed for about an hour, so they are filtered out.
    """
    found: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filter=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        found.extend(n for n in page["NatGateways"]
                     if n["State"] not in ("deleted", "deleting", "failed"))
    return found


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str,
              state: dict[str, Any]) -> None:
    """Delete the app stack, the staging bucket and the toolkit stack, poll until no remnant is
    left, and raise naming each one that is. The bootstrap template retains the staging bucket, so
    it is deleted here by name.
    """
    errors: list[str] = []
    ec2 = ctx.client("ec2")
    ecs = ctx.client("ecs")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    for label, fn in (
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        if errors:  # the app stack deletes as the toolkit's exec role: keep the toolkit for it
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket {staging} kept: "
                                 + "; ".join(errors))
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")

    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining: list[str] = ["teardown verification never ran"]
    while time.monotonic() < deadline:
        remaining = []
        for label, name in (("app stack", stack), ("toolkit stack", toolkit)):
            st = _stack_status(ctx, name)
            if st not in ("DELETE_COMPLETE", None):
                remaining.append(f"{label} {st}")
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append(f"staging bucket {staging} still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "404":
                raise
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        if state.get("cluster"):
            live = [c["clusterArn"] for c in ecs.describe_clusters(
                clusters=[state["cluster"]])["clusters"] if c["status"] != "INACTIVE"]
            if live:
                remaining.append(f"ecs cluster still active: {live!r}")
        if state.get("vpc"):
            try:
                ec2.describe_vpcs(VpcIds=[state["vpc"]])
                remaining.append(f"vpc {state['vpc']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                    raise
            nat_live = _nats_in_vpc(ec2, state["vpc"])
            if nat_live:
                remaining.append(
                    f"NAT gateways still live: "
                    f"{ {n['NatGatewayId']: n['State'] for n in nat_live} !r}")
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        time.sleep(10.0)
    else:
        errors.append(
            f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    # The VPC delete is otherwise unasserted.
    if state.get("vpc") and not errors:
        code = _error_code(lambda: ctx.client("ec2").describe_vpcs(VpcIds=[state["vpc"]]))
        if code != "InvalidVpcID.NotFound":
            errors.append(
                f"after teardown DescribeVpcs({state['vpc']!r}) failed with {code!r}, "
                f"expected 'InvalidVpcID.NotFound'")
    if errors:
        raise AssertionError("; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
