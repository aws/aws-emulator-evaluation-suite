"""put-attributes-empty-string-value-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-attributes-empty-string-value-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


# ===== helpers =====
def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _launch_container_instance(ctx, cluster_name: str) -> str:
    """PutAttributes only accepts a `container-instance` target that ECS has validated through a
    real registration -- RegisterContainerInstance requires a genuine, AWS-signed EC2 instance
    identity document that can't be fabricated. So launch a real (tiny) EC2 host running the
    ECS-optimized AMI, point it at our cluster via user-data, and wait for its agent to
    self-register. Returns the containerInstanceArn once registered."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    ecs = ctx.client("ecs")

    ami_param = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")
    ami_id = json.loads(ami_param["Parameter"]["Value"])["image_id"]

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "no shared network VPC available in this account to launch a container instance in"
    vpc_id = vpcs[0]["VpcId"]
    subnet_id = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"][0]["SubnetId"]
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]

    role_name = ctx.unique_name("sim2real-behav-ecsrole-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    )
    iam.create_instance_profile(InstanceProfileName=role_name)
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)

    def _cleanup_iam():
        for fn in (
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name),
            lambda: iam.delete_instance_profile(InstanceProfileName=role_name),
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
            ),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup_iam)

    user_data = f"#!/bin/bash\necho ECS_CLUSTER={cluster_name} >> /etc/ecs/ecs.config\n"

    instance_id = None
    last_err = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and instance_id is None:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                IamInstanceProfile={"Name": role_name},
                UserData=user_data,
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": cluster_name}]}
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
        except Exception as err:  # IAM instance-profile propagation lag
            last_err = err
            time.sleep(5)
    assert instance_id, f"could not launch the EC2 container-instance host: {last_err}"

    def _terminate():
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            return
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_terminate)

    ci_arn = None
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline and ci_arn is None:
        arns = ecs.list_container_instances(cluster=cluster_name).get("containerInstanceArns", [])
        if arns:
            ci_arn = arns[0]
        else:
            time.sleep(2)
    assert ci_arn, "EC2 host never registered as an ECS container instance within 5 minutes"

    def _deregister():
        try:
            ecs.deregister_container_instance(cluster=cluster_name, containerInstance=ci_arn, force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_deregister)
    return ci_arn


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAttributes rejects a zero-length attribute value (documented 1-128 char range) while
    still preserving an attribute with no value field at all and one with a real short value --
    ListAttributes must not collapse "no value" and "value present" into the same representation."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-behav-ecs-attrs-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]

    def _delete_cluster():
        deadline = time.monotonic() + 60
        while True:
            try:
                ecs.delete_cluster(cluster=cluster_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsContainerInstancesException",
                    "ClusterContainsTasksException",
                    "UpdateInProgressException",
                ) or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_delete_cluster)

    ci_arn = _launch_container_instance(ctx, cluster_name)

    valued_name = ctx.unique_name("sim2real-behav-ecs-attr-valued-")
    valueless_name = ctx.unique_name("sim2real-behav-ecs-attr-none-")
    empty_name = ctx.unique_name("sim2real-behav-ecs-attr-empty-")

    # Positive control 1: a real, non-empty value is stored and returned exactly.
    ecs.put_attributes(
        cluster=cluster_arn,
        attributes=[{"name": valued_name, "value": "some-value_123", "targetId": ci_arn}],
    )
    # Positive control 2: an attribute with no `value` key at all is a legal "flag" attribute.
    ecs.put_attributes(
        cluster=cluster_arn,
        attributes=[{"name": valueless_name, "targetId": ci_arn}],
    )

    def _list():
        attrs = []
        token = None
        while True:
            kwargs = {"cluster": cluster_arn, "targetType": "container-instance"}
            if token:
                kwargs["nextToken"] = token
            resp = ecs.list_attributes(**kwargs)
            attrs.extend(resp["attributes"])
            token = resp.get("nextToken")
            if not token:
                break
        return {a["name"]: a for a in attrs}

    # Poll (bounded) rather than a single read: a freshly-registered container instance's
    # attribute list can take a moment to reflect the two just-written custom attributes among
    # its many agent-reported built-in ones.
    deadline = time.monotonic() + 30
    by_name = _list()
    while (valued_name not in by_name or valueless_name not in by_name) and time.monotonic() < deadline:
        time.sleep(2)
        by_name = _list()
    assert valued_name in by_name, f"valued attribute never appeared in ListAttributes: {sorted(by_name)!r}"
    assert valueless_name in by_name, f"valueless attribute never appeared in ListAttributes: {sorted(by_name)!r}"
    assert by_name[valued_name].get("value") == "some-value_123", (
        f"expected valued attribute to keep its value 'some-value_123', got {by_name[valued_name]!r}"
    )
    assert "value" not in by_name[valueless_name], (
        f"valueless attribute should have no 'value' key, got {by_name[valueless_name]!r}"
    )

    # Negative: an explicit empty-string value violates the documented 1-128 char constraint.
    code, message = _error(
        lambda: ecs.put_attributes(
            cluster=cluster_arn,
            attributes=[{"name": empty_name, "value": "", "targetId": ci_arn}],
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "Invalid length for attribute value.", message

    # Effect absent: poll (bounded, exiting the moment the state is observed absent) instead
    # of a fixed sleep-then-check, which either races a slower backend or always pays the
    # full delay even when the answer is already available on the first read.
    deadline = time.monotonic() + 10
    by_name_after = _list()
    while empty_name in by_name_after and time.monotonic() < deadline:
        time.sleep(1)
        by_name_after = _list()
    assert empty_name not in by_name_after, "rejected empty-value attribute was persisted anyway"

    # Positive control still holds after the rejected call.
    assert by_name_after[valued_name].get("value") == "some-value_123", (
        f"expected valued attribute to still hold 'some-value_123' after the rejected call, "
        f"got {by_name_after[valued_name]!r}"
    )
    assert "value" not in by_name_after[valueless_name], (
        f"expected valueless attribute to still have no 'value' key after the rejected call, "
        f"got {by_name_after[valueless_name]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
