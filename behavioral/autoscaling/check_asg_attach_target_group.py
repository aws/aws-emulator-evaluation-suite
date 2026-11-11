"""asg-attach-target-group."""
from __future__ import annotations

import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asg-attach-target-group"
GROUP = 'load-balancing'
SERVICES = ['autoscaling']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A target group attached with AttachLoadBalancerTargetGroups is reported by
    DescribeLoadBalancerTargetGroups, and the instance the ASG launches registers in it."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    elbv2 = ctx.client("elbv2")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

    def _make_asg(min_size=0, max_size=1, desired_capacity=0):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": "t3.micro"},
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        as_.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
            MinSize=min_size,
            MaxSize=max_size,
            DesiredCapacity=desired_capacity,
            VPCZoneIdentifier=",".join(_subnet_ids()),
            HealthCheckGracePeriod=0,
        )
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _wait_for_instance_count(name, count, timeout_s=300, interval_s=10):
        deadline = time.monotonic() + timeout_s
        instances = []
        while time.monotonic() < deadline:
            group = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
                "AutoScalingGroups", []
            )
            instances = group[0].get("Instances", []) if group else []
            if len(instances) == count:
                return instances
            time.sleep(interval_s)
        raise AssertionError(f"instance count {count} not reached within {timeout_s}s")

    subnet_ids = _subnet_ids()
    vpc_id = ec2.describe_subnets(SubnetIds=subnet_ids[:1])["Subnets"][0]["VpcId"]

    tg_name = "sim2real-astg-" + ctx.unique_name("")[-8:]
    tg = elbv2.create_target_group(
        Name=tg_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        HealthCheckPath="/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]

    def _delete_tg(arn=tg_arn):
        # A target group can only be deleted once no ASG references it; ASG
        # ForceDelete detaches asynchronously, so retry ResourceInUse to a deadline.
        deadline = time.monotonic() + 60
        while True:
            try:
                elbv2.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_delete_tg)

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)

    as_.attach_load_balancer_target_groups(
        AutoScalingGroupName=name, TargetGroupARNs=[tg_arn]
    )

    attached = as_.describe_load_balancer_target_groups(AutoScalingGroupName=name)[
        "LoadBalancerTargetGroups"
    ]
    states = {x["LoadBalancerTargetGroupARN"]: x.get("State") for x in attached}
    assert tg_arn in states, f"target group not attached to ASG: {states}"
    assert states[tg_arn] in ("Adding", "Added", "InService"), states[tg_arn]

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    instances = _wait_for_instance_count(name, 1, timeout_s=300, interval_s=10)
    asg_instance_ids = {i["InstanceId"] for i in instances}
    assert asg_instance_ids, "ASG did not launch an instance"

    # Health may stay initial/unhealthy with no backend; only registration is asserted.
    def registered_ids():
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        return {d["Target"]["Id"] for d in descs}

    deadline = time.monotonic() + 300
    found = set()
    while time.monotonic() < deadline:
        found = registered_ids()
        if found & asg_instance_ids:
            break
        time.sleep(2)
    assert found & asg_instance_ids, (
        f"ASG instances {asg_instance_ids} not registered in target group; "
        f"registered={found}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
