"""container-instance-deregister-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "container-instance-deregister-not-found"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterContainerInstance rejects an unknown container instance, while the same call
    succeeds for a real registered instance on the same cluster (positive control)."""
    ecs = ctx.client("ecs")
    cluster = _create_cluster(ctx, ecs)

    ci_arn = _register_real_container_instance(ctx, ecs, cluster["clusterArn"])

    deregistered = _retry_throttled(
        lambda: ecs.deregister_container_instance(
            cluster=cluster["clusterArn"], containerInstance=ci_arn, force=True
        )
    )
    assert deregistered["containerInstance"]["containerInstanceArn"] == ci_arn

    # DescribeContainerInstances keeps reporting a deregistered instance as INACTIVE; it leaves
    # ListContainerInstances only after a short lag, hence the poll.
    listed = _poll_until(
        lambda: set(ecs.list_container_instances(cluster=cluster["clusterArn"])["containerInstanceArns"]),
        lambda s: ci_arn not in s,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert ci_arn not in listed, "deregistered instance must be absent from ListContainerInstances"

    described = ecs.describe_container_instances(cluster=cluster["clusterArn"], containerInstances=[ci_arn])
    assert not described["failures"], described["failures"]
    assert described["containerInstances"][0]["containerInstanceArn"] == ci_arn
    assert described["containerInstances"][0]["status"] == "INACTIVE", described["containerInstances"][0]["status"]

    bogus = "00000000000000000000000000000000"
    code, message = _expect_error(
        lambda: ecs.deregister_container_instance(
            cluster=cluster["clusterArn"], containerInstance=bogus, force=True
        )
    )
    assert code == "InvalidParameterException", code
    expected_message = f"Referenced container instance {bogus} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"



# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _expect_error(fn, attempts: int = 7):
    """Return the (code, message) of the error raised by *fn*, retrying through throttles.
    Raises when *fn* succeeds."""
    for i in range(attempts):
        code, message = _error(fn)
        if code not in _THROTTLE_CODES:
            return code, message
        time.sleep(min(2.0 * (2**i), 20.0))
    raise AssertionError(f"still throttled after {attempts} attempts")


def _retry_throttled(fn, attempts: int = 7, base_delay: float = 2.0):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(min(base_delay * (2**i), 20.0))
    raise last


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "InvalidInstanceID.NotFound",
            "NoSuchEntity",
        ):
            raise


def _create_cluster(ctx, ecs, name=None, **kwargs) -> dict:
    name = name or ctx.unique_name("sim2real-behav-ecs-cluster-")
    resp = _retry_throttled(lambda: ecs.create_cluster(clusterName=name, **kwargs))
    arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=arn)))
    return resp["cluster"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _register_real_container_instance(ctx, ecs, cluster_arn) -> str:
    """Register a real EC2 instance as a container instance on *cluster_arn* and return its ARN.
    RegisterContainerInstance validates the signed identity document, so it is fetched via SSM."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError("no shared network VPC subnets available to launch a real EC2 instance")
    subnet_id = subnets[0]["SubnetId"]
    vpc_id = subnets[0]["VpcId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in the shared network")
    sg_id = sgs[0]["GroupId"]

    role_name = ctx.unique_name("sim2real-ci-ssm-")
    profile_name = role_name
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    ssm_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn)
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ssm_policy_arn))
    )
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    deadline = time.monotonic() + 90.0
    instance_id = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            reservation = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ci-identity-")}],
                    }
                ],
            )
            instance_id = reservation["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            last_err = exc
            # a freshly-created instance profile isn't immediately usable by EC2 (IAM propagation)
            if code in ("InvalidParameterValue", "InvalidParameterCombination") and "profile" in str(exc).lower():
                time.sleep(5)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"RunInstances never succeeded after IAM instance-profile propagation retries: {last_err}")
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))

    # No "running" poll: DescribeInstances can briefly return InvalidInstanceID.NotFound right
    # after RunInstances, and SSM Online already implies running.
    def _ssm_ping_status():
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])[
            "InstanceInformationList"
        ]
        return info[0]["PingStatus"] if info else None

    online = _poll_until(_ssm_ping_status, lambda status: status == "Online", timeout_s=180.0, interval_s=5.0)
    if online != "Online":
        raise AssertionError(f"identity-fetch EC2 instance never registered Online with SSM (status={online!r})")

    command_id = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [
                "TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')",
                "echo ---DOC-START---",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/dynamic/instance-identity/document",
                "echo ---DOC-END---",
                "echo ---SIG-START---",
                "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/dynamic/instance-identity/signature",
                "echo ---SIG-END---",
            ]
        },
    )["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError:
            return {"Status": "Pending"}

    invocation = _poll_until(
        _invocation,
        lambda inv: inv.get("Status") in ("Success", "Failed", "Cancelled", "TimedOut"),
        timeout_s=30.0,
        interval_s=3.0,
    )
    if invocation.get("Status") != "Success":
        raise AssertionError(f"identity-document SSM command did not succeed: {invocation.get('Status')!r}")

    out = invocation["StandardOutputContent"]
    doc = out.split("---DOC-START---")[1].split("---DOC-END---")[0].strip()
    sig = out.split("---SIG-START---")[1].split("---SIG-END---")[0].strip()
    if not doc or not sig:
        raise AssertionError("identity document/signature retrieval produced empty output")

    registered = ecs.register_container_instance(
        cluster=cluster_arn,
        instanceIdentityDocument=doc,
        instanceIdentityDocumentSignature=sig,
        totalResources=[
            {"name": "CPU", "type": "INTEGER", "integerValue": 2048},
            {"name": "MEMORY", "type": "INTEGER", "integerValue": 4096},
            {"name": "PORTS", "type": "STRINGSET", "stringSetValue": []},
        ],
    )["containerInstance"]
    assert registered["status"] in ("ACTIVE", "REGISTERING"), registered["status"]
    return registered["containerInstanceArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
