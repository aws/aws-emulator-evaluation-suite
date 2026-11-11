"""create-environment-max-workers-less-than-min-workers-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-environment-max-workers-less-than-min-workers-rejected"
GROUP = "overly-permissive"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironment with MaxWorkers below MinWorkers, on a real role, subnets and security group,
    fails with ValidationException "MinWorkers must be less than or equal to MaxWorkers." and
    creates no environment.
    """
    mwaa = ctx.client("mwaa")
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mwaa-badworkers-")

    role_name = ctx.unique_name("sim2real-mwaa-badworkers-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": ["airflow.amazonaws.com", "airflow-env.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _wait_for_role_assumable(ctx, role_arn)
    subnet_ids, sg_id = _provision_network(ctx)

    code, message = _error_past_role_propagation(
        lambda: mwaa.create_environment(
            Name=name,
            ExecutionRoleArn=role_arn,
            SourceBucketArn="arn:aws:s3:::some-bucket-name",
            DagS3Path="dags",
            NetworkConfiguration={
                "SubnetIds": subnet_ids,
                "SecurityGroupIds": [sg_id],
            },
            MinWorkers=5,
            MaxWorkers=1,
        )
    )
    assert code == "ValidationException", f"actual_code={code!r}"
    assert message == "MinWorkers must be less than or equal to MaxWorkers.", f"actual_message={message!r}"

    # Effect absent: no environment record was created under that name.
    not_found_code, not_found_message = _error(lambda: mwaa.get_environment(Name=name))
    assert not_found_code == "ResourceNotFoundException", f"actual_code={not_found_code!r}"
    assert not_found_message == f"Environment {name} not found.", f"actual_message={not_found_message!r}"

    # Positive control: the mwaa API is not just blanket-rejecting every call.
    control = mwaa.list_environments(MaxResults=5)
    assert "Environments" in control, f"actual_response={control!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _error_past_role_propagation(fn, timeout_s=60.0):
    """_error(fn), retried every 2 s while CreateEnvironment refuses the fresh role as not yet
    assumable (IAM propagation), so the verdict comes from the rule under test."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error(fn)
        role_not_propagated = (
            code in ("ValidationException", "AccessDeniedException") and "role" in (message or "").lower()
        )
        if not role_not_propagated or time.monotonic() >= deadline:
            return code, message
        time.sleep(2)


def _provision_network(ctx):
    """A VPC with two subnets in two AZs and a security group: enough for CreateEnvironment's
    subnet verification to pass. No route, gateway or ENI is created, so teardown is immediate."""
    ec2 = ctx.client("ec2")
    tag_spec = lambda rt: [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": CHECK}]}]  # noqa: E731
    vpc_id = ec2.create_vpc(CidrBlock="10.193.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.193.{i}.0/24", AvailabilityZone=az, TagSpecifications=tag_spec("subnet")
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-mwaa-badworkers-sg-"),
        Description="mwaa behavioral check security group",
        TagSpecifications=tag_spec("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_ids, sg_id


def _wait_for_role_assumable(ctx, role_arn, timeout_s=30.0):
    """IAM role propagation is eventually consistent; poll GetRole before relying on it
    from CreateEnvironment, which retries its own not-yet-assumable refusal."""
    iam = ctx.client("iam")
    role_name = role_arn.rsplit("/", 1)[-1]
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError as e:
            last_err = e
        time.sleep(3)
    if last_err:
        raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
