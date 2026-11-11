#!/usr/bin/env python3
"""CDK app: a containerized service from an IMAGE ASSET, behind an ALB, logging to CloudWatch.

  ``<prefix>-main``    the wired service. `ContainerImage.from_asset` makes cdk-assets build the
                       image at deploy time and push it to the bootstrap environment's
                       container-asset repository; the Fargate service runs it behind an
                       internet-facing Application Load Balancer, ships stdout to a CloudWatch log
                       group through the awslogs driver, and a Logs metric filter over that group
                       feeds the custom metric an alarm crosses on. A second alarm watches the target
                       group's UnHealthyHostCount and is the control: it must stay OK while the
                       service is healthy.
  ``<prefix>-broken``  a task definition for the SAME published image, referenced by URI, whose
                       execution role may write logs but holds no ECR permission. The task cannot
                       retrieve registry auth, so it never starts and the awslogs driver never
                       creates a stream — the absence the negative leg asserts.

The broken variant deliberately runs in the main stack's cluster and subnets (the check passes them
to RunTask) rather than standing up a second VPC and load balancer: the withheld permission is the
subject, and a second ALB would cost more than the rest of the workflow put together.

Context:
  stack_prefix     — CloudFormation stack name prefix (carries the cleanup prefix `sim2real-xsvc-`).
  greeting         — the drift knob: a container environment change, which must produce a new task
                     definition revision and update the service IN PLACE, without re-pushing the
                     image whose content did not change.
  site_marker      — a per-run token the served body must carry, so a cached or foreign response
                     cannot pass for this deployment's.
  metric_namespace — per-run namespace for the metric-filter metric.
  image_uri        — the main stack's published image URI, passed to the BROKEN stack.
  ingress_cidrs    — comma-separated IPv4 CIDRs the ALB listener admits; the runner's own egress,
                     never 0.0.0.0/0.
"""
from aws_cdk import App, CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs

METRIC_NAME = "Requests"
CONTAINER_PORT = 8080
STREAM_PREFIX = "app"
# The literal the container prints per request and the metric filter counts. Fixed, not per-run: the
# filter is part of the deployed stack and must not change between deploys.
LOG_TOKEN = "SIM2REAL_REQUEST"


def _ctx(scope, key, default=""):
    value = scope.node.try_get_context(key)
    return default if value in (None, "") else value


class ContainerServiceStack(Stack):
    """The wired service."""

    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        namespace = _ctx(self, "metric_namespace", "sim2real/xsvc")
        greeting = _ctx(self, "greeting", "hello")
        marker = _ctx(self, "site_marker", "sim2real")

        # Public subnets and NO NAT gateway: the task needs to reach ECR and CloudWatch Logs, a
        # public IP gives it that, and a NAT gateway would add minutes to both create and destroy
        # plus an hourly charge for a check that runs for one.
        vpc = ec2.Vpc(
            self,
            "Vpc",
            max_azs=2,
            nat_gateways=0,
            ip_addresses=ec2.IpAddresses.cidr("10.60.0.0/16"),
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24
                )
            ],
        )
        cluster = ecs.Cluster(self, "Cluster", vpc=vpc)
        log_group = logs.LogGroup(
            self,
            "ServiceLogs",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        task = ecs.FargateTaskDefinition(self, "Task", cpu=256, memory_limit_mib=512)
        task.add_container(
            "app",
            # THE POINT OF THIS WORKFLOW: an image asset. `from_asset` builds container/Dockerfile at
            # deploy time and pushes it to the bootstrap container-asset repository under its content
            # hash — the path `_deploy_cdk`'s synth-and-strip helper cannot express at all.
            image=ecs.ContainerImage.from_asset("container"),
            logging=ecs.LogDrivers.aws_logs(stream_prefix=STREAM_PREFIX, log_group=log_group),
            environment={
                "GREETING": greeting,
                "SITE_MARKER": marker,
                "PORT": str(CONTAINER_PORT),
            },
            port_mappings=[ecs.PortMapping(container_port=CONTAINER_PORT)],
        )
        service = ecs.FargateService(
            self,
            "Service",
            cluster=cluster,
            task_definition=task,
            desired_count=1,
            assign_public_ip=True,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            # A replacement task comes up BEFORE the old one goes away, so the drift leg can assert
            # the load balancer keeps answering across the task-definition swap.
            min_healthy_percent=100,
            max_healthy_percent=200,
        )
        # `open=False`: the default would admit 0.0.0.0/0. Only the runner's own egress, read back
        # from `ingress_cidrs`, may reach the listener.
        ingress_cidrs = [c for c in _ctx(self, "ingress_cidrs", "").split(",") if c]
        assert ingress_cidrs, "no ingress CIDR in context — the ALB would be unreachable AND unsafe"
        alb = elbv2.ApplicationLoadBalancer(self, "Alb", vpc=vpc, internet_facing=True)
        listener = alb.add_listener("Http", port=80, open=False)
        for cidr in ingress_cidrs:
            listener.connections.allow_default_port_from(ec2.Peer.ipv4(cidr))
        target_group = listener.add_targets(
            "App",
            port=CONTAINER_PORT,
            protocol=elbv2.ApplicationProtocol.HTTP,
            targets=[service],
            health_check=elbv2.HealthCheck(
                path="/healthz",
                interval=Duration.seconds(15),
                timeout=Duration.seconds(5),
                healthy_threshold_count=2,
            ),
            deregistration_delay=Duration.seconds(10),
        )

        metric_filter = logs.MetricFilter(
            self,
            "RequestFilter",
            log_group=log_group,
            filter_pattern=logs.FilterPattern.literal(f'"{LOG_TOKEN}"'),
            metric_namespace=namespace,
            metric_name=METRIC_NAME,
            metric_value="1",
        )
        request_alarm = cloudwatch.Alarm(
            self,
            "RequestAlarm",
            metric=metric_filter.metric(statistic="Sum", period=Duration.minutes(1)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            # MISSING so the alarm STARTS in INSUFFICIENT_DATA and the crossing is assertable.
            treat_missing_data=cloudwatch.TreatMissingData.MISSING,
        )
        unhealthy_alarm = cloudwatch.Alarm(
            self,
            "UnhealthyAlarm",
            metric=target_group.metric_unhealthy_host_count(
                period=Duration.minutes(1), statistic="Maximum"
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            # NOT_BREACHING: this one is the CONTROL. It must sit in OK while the service is healthy,
            # so a target that flips every alarm to ALARM fails the workflow instead of passing it.
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        CfnOutput(self, "LoadBalancerDns", value=alb.load_balancer_dns_name)
        CfnOutput(self, "LoadBalancerArn", value=alb.load_balancer_arn)
        CfnOutput(self, "TargetGroupArn", value=target_group.target_group_arn)
        CfnOutput(self, "ClusterName", value=cluster.cluster_name)
        CfnOutput(self, "ServiceName", value=service.service_name)
        CfnOutput(self, "ServiceArn", value=service.service_arn)
        CfnOutput(self, "TaskDefinitionArn", value=task.task_definition_arn)
        CfnOutput(self, "LogGroupName", value=log_group.log_group_name)
        CfnOutput(self, "StreamPrefix", value=STREAM_PREFIX)
        CfnOutput(self, "RequestAlarmName", value=request_alarm.alarm_name)
        CfnOutput(self, "UnhealthyAlarmName", value=unhealthy_alarm.alarm_name)
        CfnOutput(self, "MetricNamespace", value=namespace)
        CfnOutput(self, "MetricName", value=METRIC_NAME)
        CfnOutput(self, "Greeting", value=greeting)
        CfnOutput(self, "SiteMarker", value=marker)
        CfnOutput(
            self,
            "Subnets",
            value=",".join(vpc.select_subnets(subnet_type=ec2.SubnetType.PUBLIC).subnet_ids),
        )
        CfnOutput(
            self,
            "SecurityGroupId",
            value=service.connections.security_groups[0].security_group_id,
        )


class ContainerServiceBrokenStack(Stack):
    """The same published image, one permission short.

    `ContainerImage.from_registry` rather than `from_asset` is what makes the break expressible:
    `from_asset` grants the task's execution role pull access to the asset repository automatically,
    so an asset-referencing task definition can never be missing it.
    """

    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        image_uri = _ctx(self, "image_uri")
        log_group = logs.LogGroup(
            self,
            "BrokenLogs",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        execution_role = iam.Role(
            self, "BrokenExec", assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com")
        )
        # Everything a task execution role normally has EXCEPT the ECR grants: the log destination
        # is reachable, so a missing stream cannot be blamed on the logging side.
        execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"{log_group.log_group_arn}:*"],
            )
        )
        task = ecs.FargateTaskDefinition(
            self, "BrokenTask", cpu=256, memory_limit_mib=512, execution_role=execution_role
        )
        task.add_container(
            "app",
            image=ecs.ContainerImage.from_registry(image_uri),
            logging=ecs.LogDrivers.aws_logs(stream_prefix=STREAM_PREFIX, log_group=log_group),
            port_mappings=[ecs.PortMapping(container_port=CONTAINER_PORT)],
        )

        CfnOutput(self, "BrokenTaskDefinitionArn", value=task.task_definition_arn)
        CfnOutput(self, "BrokenLogGroupName", value=log_group.log_group_name)


app = App()
_PREFIX = app.node.try_get_context("stack_prefix") or "SimParityCdkContainerService"
ContainerServiceStack(app, f"{_PREFIX}-main")
ContainerServiceBrokenStack(app, f"{_PREFIX}-broken")
app.synth()
