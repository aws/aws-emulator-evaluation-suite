"""list-experiment-resolved-targets-reflects-server-side-resolution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-experiment-resolved-targets-reflects-server-side-resolution"
GROUP = "server-side"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """ListExperimentResolvedTargets reflects FIS's own resourceTags resolution against live EC2:
    exactly the one tagged instance, never the untagged decoy created alongside it."""
    ec2 = ctx.client("ec2")
    fis = ctx.client("fis")

    tag_key = "sim2real-fis-target"
    tag_value = ctx.unique_name("rt-")
    ami_id = _latest_amazon_linux_ami(ctx)
    subnet_id = _default_subnet_id(ctx)

    instance_id = _launch_instance(
        ctx, ami_id, subnet_id,
        extra_tags=[{"Key": tag_key, "Value": tag_value}],
        name=ctx.unique_name("sim2real-fis-"),
    )
    decoy_instance_id = _launch_instance(
        ctx, ami_id, subnet_id,
        extra_tags=[],
        name=ctx.unique_name("sim2real-fis-decoy-"),
    )

    for iid in (instance_id, decoy_instance_id):
        _poll_until(
            lambda iid=iid: ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["State"]["Name"],
            lambda s: s == "running",
            timeout_s=180,
            interval_s=5,
        )

    role_arn = _create_fis_role(ctx, policy_statements=[
        {"Effect": "Allow", "Action": ["ec2:RebootInstances", "ec2:DescribeInstances"], "Resource": "*"},
    ])
    template_id = _create_ec2_reboot_template(ctx, role_arn, tag_key, tag_value)

    resp = _start_experiment_with_retry(ctx, template_id)
    experiment_id = resp["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))

    resolved = _poll_until(
        lambda: _list_resolved_targets_or_pending(fis, experiment_id),
        lambda targets: len(targets) >= 1,
        timeout_s=90,
        interval_s=3,
    )

    assert len(resolved) == 1, f"expected exactly 1 resolved target for the tag-filtered template, got {resolved!r}"
    target = resolved[0]
    assert target["resourceType"] == "aws:ec2:instance", f"expected resourceType 'aws:ec2:instance', got {target!r}"
    assert target["targetName"] == "taggedInstance", f"expected targetName 'taggedInstance', got {target!r}"
    info_values = " ".join(str(v) for v in target.get("targetInformation", {}).values())
    assert instance_id in info_values, (
        f"expected resolved targetInformation to reference the tagged instance {instance_id}, got {info_values!r}"
    )
    assert decoy_instance_id not in info_values, (
        f"resolved target must not reference the untagged decoy instance {decoy_instance_id}"
        f" -- resolution is not filtering by resourceTags: {info_values!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _latest_amazon_linux_ami(ctx):
    ec2 = ctx.client("ec2")
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI available in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _default_subnet_id(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to launch the target EC2 instances")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch the target EC2 instances into")
    return subnets[0]["SubnetId"]


def _launch_instance(ctx, ami_id, subnet_id, *, extra_tags, name):
    ec2 = ctx.client("ec2")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": name}, *extra_tags],
        }],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    return instance_id


def _create_fis_role(ctx, policy_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-fis-policy-")
        doc = {"Version": "2012-10-17", "Statement": policy_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))

        def _cleanup_policy():
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_cleanup_policy)
    return role_arn


def _delete_template_safe(ctx, template_id):
    fis = ctx.client("fis")
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_ec2_reboot_template(ctx, role_arn, tag_key, tag_value):
    fis = ctx.client("fis")
    kwargs = dict(
        clientToken=ctx.unique_name("tmpl-"),
        description="sim2real fis resolved-targets check",
        stopConditions=[{"source": "none"}],
        targets={
            "taggedInstance": {
                "resourceType": "aws:ec2:instance",
                "resourceTags": {tag_key: tag_value},
                "selectionMode": "ALL",
            },
        },
        actions={
            "rebootAction": {
                "actionId": "aws:ec2:reboot-instances",
                "targets": {"Instances": "taggedInstance"},
            },
        },
        roleArn=role_arn,
    )

    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = fis.create_experiment_template(**kwargs)
            template_id = resp["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_safe(ctx, template_id))
            return template_id
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "ResourceNotFoundException"):
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _list_resolved_targets_or_pending(fis, experiment_id):
    """ListExperimentResolvedTargets raises ValidationException("Target resolution is ongoing.
    Retry after target resolution ends.") while resolution is still in flight; treat that as
    "not resolved yet" for the poll rather than letting it propagate as an unhandled error."""
    try:
        return fis.list_experiment_resolved_targets(experimentId=experiment_id).get("resolvedTargets", [])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message", "")
        if code == "ValidationException" and "resolution is ongoing" in message.lower():
            return []
        raise


def _start_experiment_with_retry(ctx, template_id, timeout_s=60.0):
    """StartExperiment can transiently fail with ValidationException("Unable to assume role ...")
    while a freshly-created IAM role/policy attachment is still propagating through STS; retry
    until that clears or the timeout elapses."""
    fis = ctx.client("fis")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(clientToken=ctx.unique_name("start-"), experimentTemplateId=template_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in message.lower():
                last_exc = e
                time.sleep(3)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _safe_stop(ctx, experiment_id):
    fis = ctx.client("fis")
    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
