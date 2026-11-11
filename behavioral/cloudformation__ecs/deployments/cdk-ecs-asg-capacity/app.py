"""cdk-ecs-asg-capacity - ecs.Cluster + an ASG capacity provider, all L2 defaults.

What this app exists to expose is narrower: `enable_managed_scaling=True` is three words of
CDK that make ECS ITSELF create infrastructure CDK never declares - a target-tracking
scaling policy on the ASG that appears in NO CloudFormation template. Synthesized offline,
this app yields ZERO AWS::AutoScaling::ScalingPolicy resources, which is the premise
that assertion rests on. The deployed side also has to produce a launch template carrying the
right ECS_CLUSTER user data, an instance profile with the right managed policy, and egress to
the ECS control plane.

nat_gateways=1: the container instance needs egress to reach ECS, and one
NAT is enough for one instance.

cdk.json pins `@aws-cdk/aws-autoscaling:generateLaunchTemplateInsteadOfLaunchConfig: true`. Without
it aws-cdk-lib 2.263.0 emits `AWS::AutoScaling::LaunchConfiguration`, which AWS refuses to
create in any account that did not already have launch configurations, so the deploy would fail for
a reason that is not fidelity.
"""
import os

import aws_cdk as cdk
from aws_cdk import aws_autoscaling as autoscaling, aws_ec2 as ec2, aws_ecs as ecs


class EcsCapacityStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc(self, "V", ip_addresses=ec2.IpAddresses.cidr("10.69.0.0/16"),
                      max_azs=2, nat_gateways=1)
        cluster = ecs.Cluster(self, "C", vpc=vpc, container_insights_v2=ecs.ContainerInsights.DISABLED)

        asg = autoscaling.AutoScalingGroup(
            self, "Asg", vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            instance_type=ec2.InstanceType("t3.small"),
            machine_image=ecs.EcsOptimizedImage.amazon_linux2023(),
            min_capacity=1, max_capacity=1, desired_capacity=1,
        )
        provider = ecs.AsgCapacityProvider(
            self, "Cap", auto_scaling_group=asg,
            enable_managed_termination_protection=False,
            enable_managed_scaling=True,
            # ECS-native managed draining: the app then synthesizes no Lambda function and no SNS
            # topic, where the default adds a Lambda+SNS drain hook and an ASG lifecycle hook, a
            # property separate from "the capacity registers".
            enable_managed_draining=True,
        )
        cluster.add_asg_capacity_provider(provider)

        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "ClusterName", value=cluster.cluster_name)
        cdk.CfnOutput(self, "CapacityProviderName", value=provider.capacity_provider_name)
        cdk.CfnOutput(self, "AsgName", value=asg.auto_scaling_group_name)
        cdk.CfnOutput(self, "PrivateSubnetIds",
                      value=cdk.Fn.join(",", [s.subnet_id for s in vpc.private_subnets]))
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
EcsCapacityStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                        region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
