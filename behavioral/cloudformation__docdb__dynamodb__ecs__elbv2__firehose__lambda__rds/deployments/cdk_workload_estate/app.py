#!/usr/bin/env python3
"""A nine-stack workload estate wired by cross-stack references.

A VPC with an internal ALB, then storage, monitoring, a database tier, Lambda, ECS, EC2,
DocumentDB/Athena/NLB and a set of access roles. Nothing is reachable from outside the VPC: the
load balancers are internal, every security group admits only the VPC CIDR or a named source
group, and tasks, the instance and the databases sit in private subnets without public IPs.

Context:
  account, region -- the environment
  prefix          -- stack ids are "<prefix>-<Part>"; every fixed physical name starts with it
  qualifier       -- bootstrap qualifier (the Lambda layer and the custom-resource handlers are
                     file assets)
  azs             -- comma-separated availability zones, the answer to the VPC's zone lookup
"""
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Duration, RemovalPolicy, Tags
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_athena as athena
from aws_cdk import aws_autoscaling as autoscaling
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_docdb as docdb
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kinesisfirehose as firehose
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_rds as rds
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from aws_cdk import aws_sqs as sqs

_HERE = Path(__file__).resolve().parent
_INLINE_HANDLER = "exports.handler = async (event) => console.log(event)"
_IIS_IMAGE = "mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"


def export(stack: cdk.Stack, name: str, value: str, description: str | None = None) -> None:
    """An output exported as "<stack name>-<name>"."""
    cdk.CfnOutput(stack, name, value=value, export_name=f"{stack.stack_name}-{name}",
                  description=description)


def _secure_bucket(scope, construct_id: str, **kwargs) -> s3.Bucket:
    """A private, SSE-S3, TLS-only bucket deleted with its objects."""
    return s3.Bucket(
        scope, construct_id,
        removal_policy=RemovalPolicy.DESTROY,
        auto_delete_objects=True,
        enforce_ssl=True,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        encryption=s3.BucketEncryption.S3_MANAGED,
        **kwargs,
    )


class AccessRolesStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        account_id = self.account

        vectors_read_only = iam.ManagedPolicy(
            self, "S3VectorsReadOnlyAccess",
            managed_policy_name=f"{prefix}-s3vectors-ro",
            description="Read-only access to S3 Vectors operations",
            statements=[
                iam.PolicyStatement(
                    sid="AllowS3VectorsReadOnlyAccess",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3vectors:ListVectors",
                        "s3vectors:GetVectors",
                        "s3vectors:GetIndex",
                        "s3vectors:GetVectorBucket",
                        "s3vectors:GetVectorBucketPolicy",
                        "s3vectors:ListIndexes",
                        "s3vectors:ListTagsForResource",
                        "s3vectors:ListVectorBuckets",
                        "s3vectors:QueryVectors",
                    ],
                    resources=["*"],
                ),
            ],
        )

        readonly = iam.Role(
            self, "ReadOnlyRole",
            role_name=f"{prefix}-readonly",
            assumed_by=iam.AccountPrincipal(account_id),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3TablesReadOnlyAccess"),
                vectors_read_only,
            ],
        )

        # The operator role reads the account; it is never granted write or administrator access.
        admin = iam.Role(
            self, "AdminRole",
            role_name=f"{prefix}-admin",
            assumed_by=iam.AccountPrincipal(account_id),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("ReadOnlyAccess"),
            ],
        )

        # Bedrock's service role: nothing in the estate invokes a model, so it holds no policy.
        bedrock = iam.Role(
            self, "BedrockRole",
            role_name=f"{prefix}-bedrock",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
        )

        export(self, "ReadOnlyRoleName", readonly.role_name)
        export(self, "AdminRoleName", admin.role_name)
        export(self, "BedrockRoleName", bedrock.role_name)
        export(self, "VectorsPolicyName", vectors_read_only.managed_policy_name)


class NetworkingStack(cdk.Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = ec2.Vpc(
            self, "ResourcesVpc",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=24, name="Public",
                                        subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=24, name="Private",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ],
        )

        alb_logs_bucket = _secure_bucket(self, "alb-access-logs-bucket")

        self.alb = elbv2.ApplicationLoadBalancer(self, "TestALB", vpc=self.vpc,
                                                 internet_facing=False)
        # The listener is not opened to any address; only the VPC itself reaches port 80.
        self.alb.connections.allow_from(ec2.Peer.ipv4(self.vpc.vpc_cidr_block), ec2.Port.tcp(80),
                                        "HTTP from inside the VPC")
        self.alb.log_access_logs(alb_logs_bucket)
        # Empty the log bucket only once the load balancer writing into it is gone.
        alb_logs_bucket.node.find_child("AutoDeleteObjectsCustomResource").node.add_dependency(self.alb)

        export(self, "VpcId", self.vpc.vpc_id)
        export(self, "AlbArn", self.alb.load_balancer_arn)
        export(self, "AlbDnsName", self.alb.load_balancer_dns_name)
        export(self, "AlbLogsBucketName", alb_logs_bucket.bucket_name)


class S3StorageStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        iot_data_bucket = _secure_bucket(self, "my-iot-data-archive")
        order_archives_bucket = _secure_bucket(self, "orders-archive-bucket")
        lifecycle_bucket = _secure_bucket(
            self, "lifecycle-bucket",
            lifecycle_rules=[
                s3.LifecycleRule(
                    tag_filters={"shouldDelete": "true"},
                    id="orders-archive-bucket-lifecycle-rule",
                    enabled=True,
                    expiration=Duration.days(1),
                ),
            ],
        )

        export(self, "IotDataBucketName", iot_data_bucket.bucket_name)
        export(self, "OrderArchivesBucketName", order_archives_bucket.bucket_name)
        export(self, "LifeCycleBucket", lifecycle_bucket.bucket_name)

        # The analytics data export targets a bucket owned by another account (BucketAccountId),
        # so the destination is deliberately not a bucket in this account.
        destination_account_id = "111122223333"
        destination_arn = (
            f"arn:{self.partition}:s3:::business-analytics-destination-data-bucket-"
            f"{destination_account_id}"
        )
        analytics_bucket_name = f"{prefix}-analytics-src-{self.account}"
        s3.CfnBucket(
            self, "AnalyticsSourceBucket",
            bucket_name=analytics_bucket_name,
            public_access_block_configuration=s3.CfnBucket.PublicAccessBlockConfigurationProperty(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
            analytics_configurations=[
                s3.CfnBucket.AnalyticsConfigurationProperty(
                    id="testAnalyticsConfiguration",
                    storage_class_analysis=s3.CfnBucket.StorageClassAnalysisProperty(
                        data_export=s3.CfnBucket.DataExportProperty(
                            destination=s3.CfnBucket.DestinationProperty(
                                bucket_arn=destination_arn,
                                bucket_account_id=destination_account_id,
                                format="CSV",
                            ),
                            output_schema_version="V_1",
                        ),
                    ),
                ),
            ],
        )
        export(self, "AnalyticsBucketName", analytics_bucket_name)

        website_hosting_bucket = s3.Bucket(
            self, "WebsiteHostingBucket",
            website_index_document="index.html",
            public_read_access=False,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            auto_delete_objects=True,
        )
        export(self, "WebsiteHostingBucketName", website_hosting_bucket.bucket_name,
               "Name of the S3 bucket with website hosting enabled")

        inventory_bucket = _secure_bucket(self, "InventoryBucket")
        inventory_destination_bucket = _secure_bucket(self, "InventoryDestinationBucket")
        inventory_bucket.add_inventory(
            destination=s3.InventoryDestination(bucket=inventory_destination_bucket),
            frequency=s3.InventoryFrequency.DAILY,
            include_object_versions=s3.InventoryObjectVersion.CURRENT,
            objects_prefix="inventory-data",
        )
        export(self, "InventoryBucketName", inventory_bucket.bucket_name)

        metrics_bucket = _secure_bucket(self, "MetricsBucket")
        metrics_bucket.add_metric(id="EntireBucket")
        metrics_bucket.add_metric(id="ImportantPrefix", prefix="important/")
        metrics_bucket.add_metric(id="ImportantTag", tag_filters={"priority": "high"})
        export(self, "MetricsBucketName", metrics_bucket.bucket_name)


class MonitoringStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        dashboard = cloudwatch.Dashboard(self, "MyDashboard",
                                         dashboard_name=f"{prefix}-service-metrics")
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="NAT Gateway Metrics",
                left=[cloudwatch.Metric(namespace="AWS/ECS", metric_name="MemoryUtilization",
                                        dimensions_map={"ClusterName": "placeholder"})],
            ),
            cloudwatch.GraphWidget(
                title="Lambda Function Metrics",
                left=[cloudwatch.Metric(namespace="AWS/Lambda", metric_name="Invocations",
                                        dimensions_map={"FunctionName": "my-data-exporter"})],
            ),
            cloudwatch.GraphWidget(
                title="ECS Cluster Metrics",
                left=[cloudwatch.Metric(namespace="AWS/ECS", metric_name="CPUUtilization",
                                        dimensions_map={"ClusterName": "placeholder"})],
            ),
        )

        destination_bucket = s3.Bucket(
            self, "FirehoseDestinationBucket",
            bucket_name=f"{prefix}-firehose-dest-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            auto_delete_objects=True,
        )

        # Identity-based grants for the auto-delete handler, so emptying this fixed-name bucket
        # never depends on the bucket policy still naming the handler's role.
        provider = self.node.try_find_child("Custom::S3AutoDeleteObjectsCustomResourceProvider")
        if provider is not None:
            provider.add_to_role_policy({
                "Effect": "Allow",
                "Action": ["s3:GetBucket*", "s3:List*", "s3:DeleteObject*", "s3:PutBucketPolicy"],
                "Resource": [destination_bucket.bucket_arn, f"{destination_bucket.bucket_arn}/*"],
            })

        firehose_role = iam.Role(self, "FirehoseRole",
                                 assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"))
        destination_bucket.grant_read_write(firehose_role)

        delivery_stream_name = f"{prefix}-delivery"
        delivery_stream = firehose.CfnDeliveryStream(
            self, "MyFirehoseDeliveryStream",
            delivery_stream_name=delivery_stream_name,
            s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=destination_bucket.bucket_arn,
                buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                    interval_in_seconds=60, size_in_m_bs=1),
                compression_format="GZIP",
                role_arn=firehose_role.role_arn,
            ),
        )
        # Create the stream only once its role's S3 grant (a separate policy) exists.
        delivery_stream.node.add_dependency(firehose_role)
        # A stack delete removes a resource before what it depends on. The stream depends on the
        # bucket's auto-delete handler, so it is gone, its last buffer flushed, before the bucket is
        # emptied; otherwise the stream refills the bucket after the handler empties it.
        delivery_stream.node.add_dependency(
            destination_bucket.node.find_child("AutoDeleteObjectsCustomResource"))

        metric_stream_role = iam.Role(
            self, "MetricStreamRole",
            assumed_by=iam.ServicePrincipal("streams.metrics.cloudwatch.amazonaws.com"))
        metric_stream_role.add_to_policy(iam.PolicyStatement(
            actions=["firehose:PutRecord", "firehose:PutRecordBatch"],
            resources=[delivery_stream.attr_arn],
        ))

        metric_stream95_role = iam.Role(
            self, "MetricStream95Role",
            assumed_by=iam.ServicePrincipal("streams.metrics.cloudwatch.amazonaws.com"))
        metric_stream95_role.add_to_policy(iam.PolicyStatement(
            actions=["firehose:PutRecord", "firehose:PutRecordBatch", "s3:PutObject",
                     "s3:GetBucketAcl", "s3:GetBucketPolicy"],
            resources=["*"],
        ))

        metric_stream95 = cloudwatch.CfnMetricStream(
            self, "MetricStream95",
            firehose_arn=delivery_stream.attr_arn,
            role_arn=metric_stream95_role.role_arn,
            include_filters=[
                cloudwatch.CfnMetricStream.MetricStreamFilterProperty(namespace="AWS/EC2"),
                cloudwatch.CfnMetricStream.MetricStreamFilterProperty(namespace="AWS/Lambda"),
            ],
            output_format="json",
            statistics_configurations=[
                cloudwatch.CfnMetricStream.MetricStreamStatisticsConfigurationProperty(
                    include_metrics=[
                        cloudwatch.CfnMetricStream.MetricStreamStatisticsMetricProperty(
                            namespace="AWS/EC2", metric_name="CPUUtilization"),
                        cloudwatch.CfnMetricStream.MetricStreamStatisticsMetricProperty(
                            namespace="AWS/Lambda", metric_name="Duration"),
                    ],
                    additional_statistics=["p95"],
                ),
            ],
        )
        # Like the other stream: create it only after its role's inline policy and the delivery stream.
        metric_stream95.node.add_dependency(metric_stream95_role)
        metric_stream95.node.add_dependency(delivery_stream)

        metric_stream = cloudwatch.CfnMetricStream(
            self, "MyCfnMetricStream",
            firehose_arn=delivery_stream.attr_arn,
            output_format="json",
            role_arn=metric_stream_role.role_arn,
            exclude_filters=[
                cloudwatch.CfnMetricStream.MetricStreamFilterProperty(
                    namespace="AWS/EC2",
                    metric_names=["CPUUtilization", "NetworkIn", "NetworkOut", "DiskReadBytes",
                                  "DiskWriteBytes"],
                ),
            ],
            statistics_configurations=[
                cloudwatch.CfnMetricStream.MetricStreamStatisticsConfigurationProperty(
                    additional_statistics=["p99"],
                    include_metrics=[
                        cloudwatch.CfnMetricStream.MetricStreamStatisticsMetricProperty(
                            namespace="AWS/ECS", metric_name="CPUUtilization"),
                    ],
                ),
            ],
            include_linked_accounts_metrics=False,
            name=f"{prefix}-stream",
        )
        metric_stream.node.add_dependency(metric_stream_role)
        metric_stream.node.add_dependency(delivery_stream)

        log_group = logs.LogGroup(self, "MyLogGroup", removal_policy=RemovalPolicy.DESTROY)
        log_stream = logs.LogStream(self, "MyLogStream", log_group=log_group,
                                    log_stream_name="MyLogStream",
                                    removal_policy=RemovalPolicy.DESTROY)

        sensor_alerts = sns.Topic(self, "my-sensor-alerts", topic_name=f"{prefix}-sensor-alerts")
        alert_queue = sqs.Queue(self, "AlertQueue", queue_name=f"{prefix}-alert-queue",
                                removal_policy=RemovalPolicy.DESTROY)

        export(self, "DashboardName", dashboard.dashboard_name)
        export(self, "DashboardArn", dashboard.dashboard_arn)
        export(self, "MetricStream95Name", metric_stream95.attr_arn)
        export(self, "MetricStreamArn", metric_stream.attr_arn,
               "Arn of the CloudWatch Metric Stream")
        export(self, "MetricStreamName", metric_stream.name,
               "Name of the CloudWatch Metric Stream")
        export(self, "FirehoseDeliveryStreamName",
               delivery_stream_name,
               "Name of the Kinesis Firehose Delivery Stream")
        export(self, "FirehoseDestinationBucketName", destination_bucket.bucket_name,
               "Name of the S3 bucket for Kinesis Firehose destination")
        export(self, "LogStream", log_stream.log_stream_name)
        export(self, "LogGroup", log_group.log_group_name)
        export(self, "SensorAlertsTopicName", sensor_alerts.topic_name)
        export(self, "SensorAlertsTopicArn", sensor_alerts.topic_arn)
        export(self, "MyAlertQueueSQSURL", alert_queue.queue_url)


class DatabaseStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, vpc: ec2.IVpc, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        allocated_storage = 20
        instance = rds.DatabaseInstance(
            self, "TestRDS",
            engine=rds.DatabaseInstanceEngine.MYSQL,
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            allocated_storage=allocated_storage,
            removal_policy=RemovalPolicy.DESTROY,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            publicly_accessible=False,
        )
        instance.node.add_dependency(vpc)

        export(self, "RdsEndpointAllocatedStorage", str(allocated_storage))
        export(self, "RdsEndpoint", instance.instance_endpoint.hostname)
        export(self, "RdsInstanceId", instance.instance_identifier)

        event_logs = dynamodb.Table(
            self, "my-event-logs",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        )
        export(self, "EventLogsTableName", event_logs.table_name)
        export(self, "EventLogsTableArn", event_logs.table_arn)

        customer_orders = dynamodb.Table(
            self, "my-customer-orders",
            partition_key=dynamodb.Attribute(name="orderId", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        )
        export(self, "CustomerOrdersTableName", customer_orders.table_name)
        export(self, "CustomerOrdersTableArn", customer_orders.table_arn)


class LambdaMiscStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, vpc: ec2.IVpc, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # An SNS-triggered function with a queue it may send to.
        connected_topic = sns.Topic(self, "ConnectedSNSTopic",
                                    topic_name=f"{prefix}-connected-topic")
        connected_log_group = logs.LogGroup(self, "ConnectedLambdaLogGroup",
                                            removal_policy=RemovalPolicy.DESTROY)
        connected_fn = lambda_.Function(
            self, "ConnectedLambda",
            log_group=connected_log_group,
            runtime=lambda_.Runtime.NODEJS_20_X,
            code=lambda_.InlineCode(_INLINE_HANDLER),
            handler="index.handler",
        )
        connected_queue = sqs.Queue(self, "ConnectedSQS", queue_name=f"{prefix}-connected-queue")
        connected_queue.grant_send_messages(connected_fn)
        connected_topic.add_subscription(sns_subscriptions.LambdaSubscription(connected_fn))

        # Two AWS integrations naming the same function: /process's credentials role has no
        # lambda:InvokeFunction, so it cannot invoke; /served's role may. No deployment is created,
        # so neither is reachable from outside the account; TestInvokeMethod exercises both.
        api_role = iam.Role(self, "ConnectedApiRole",
                            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"))
        served_role = iam.Role(self, "ConnectedApiServedRole",
                               assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"))
        connected_fn.grant_invoke(served_role)
        api = apigateway.RestApi(self, "ConnectedApi", rest_api_name=f"{prefix}-connected-api",
                                 deploy=False)
        api.root.add_resource("process").add_method("POST", apigateway.AwsIntegration(
            service="lambda",
            path=f"2015-03-31/functions/{connected_fn.function_arn}/invocations",
            options=apigateway.IntegrationOptions(credentials_role=api_role),
        ))
        # /served maps the function's 200 to a method 200; without it a served call ends in 500.
        api.root.add_resource("served").add_method(
            "POST",
            apigateway.AwsIntegration(
                service="lambda",
                path=f"2015-03-31/functions/{connected_fn.function_arn}/invocations",
                options=apigateway.IntegrationOptions(
                    credentials_role=served_role,
                    integration_responses=[apigateway.IntegrationResponse(status_code="200")],
                ),
            ),
            method_responses=[apigateway.MethodResponse(status_code="200")],
        )

        export(self, "ConnectedSQSURL", connected_queue.queue_url)
        export(self, "ConnectedSNSTopicName", connected_topic.topic_name)
        export(self, "ConnectedLambdaName", connected_fn.function_name)
        export(self, "ConnectedLambdaRuntime", connected_fn.runtime.to_string())
        export(self, "ConnectedSQSName", connected_queue.queue_name)

        tagged_log_group = logs.LogGroup(self, "TaggedLambdaLogGroup",
                                         removal_policy=RemovalPolicy.DESTROY)
        tagged_fn = lambda_.Function(
            self, "TaggedLambda",
            log_group=tagged_log_group,
            runtime=lambda_.Runtime.NODEJS_20_X,
            handler="index.handler",
            code=lambda_.InlineCode(_INLINE_HANDLER),
            vpc=vpc,
        )
        Tags.of(tagged_fn).add("lambda-console:blueprint", "true")
        export(self, "TaggedLambdaName", tagged_fn.function_name, "Name of Lambda with tags")

        concurrent_log_group = logs.LogGroup(self, "ConcurrentLambdaLogGroup",
                                             removal_policy=RemovalPolicy.DESTROY)
        concurrent_fn = lambda_.Function(
            self, "ConcurrentLambda",
            log_group=concurrent_log_group,
            function_name=f"{prefix}-trigger-workflow",
            runtime=lambda_.Runtime.NODEJS_20_X,
            handler="index.handler",
            code=lambda_.InlineCode(_INLINE_HANDLER),
            vpc=vpc,
        )
        concurrent_fn.current_version.add_alias("prod")
        export(self, "ConcurrentLambdaName", concurrent_fn.function_name,
               "Name of the Lambda function with a prod alias")

        layer = lambda_.LayerVersion(
            self, "S3Layer",
            code=lambda_.Code.from_asset(str(_HERE / "lambda" / "fetch-instance-ids")),
            compatible_runtimes=[lambda_.Runtime.NODEJS_20_X],
            removal_policy=RemovalPolicy.DESTROY,
        )
        export(self, "S3LayerArnExport", layer.layer_version_arn,
               "ARN of the Lambda layer from s3")

        athena_role = iam.Role(self, "AthenaLambdaRole",
                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        docdb_role = iam.Role(self, "DocDBLambdaRole",
                              assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        exporter_role = iam.Role(self, "ExporterRole",
                                 assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        export(self, "AthenaLambdaRoleName", athena_role.role_name)
        export(self, "AthenaLambdaRoleArn", athena_role.role_arn)
        export(self, "DocDBLambdaRoleName", docdb_role.role_name)
        export(self, "DocDBLambdaRoleArn", docdb_role.role_arn)
        export(self, "ExporterRoleName", exporter_role.role_name)
        export(self, "ExporterRoleArn", exporter_role.role_arn)


class EcsStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, vpc: ec2.IVpc,
                 alb: elbv2.IApplicationLoadBalancer, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        cluster_capacity = 2
        cluster = ecs.Cluster(self, "my-data-cluster", vpc=vpc, container_insights=True)

        asg_instance_role = iam.Role(
            self, "ASGInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonEC2ContainerServiceforEC2Role"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"),
            ],
        )
        launch_template = ec2.LaunchTemplate(
            self, "ASGLaunchTemplate",
            role=asg_instance_role,
            machine_image=ecs.EcsOptimizedImage.amazon_linux2023(),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            require_imdsv2=True,
            user_data=ec2.UserData.for_linux(),
        )
        asg = autoscaling.AutoScalingGroup(self, "DefaultAutoScalingGroup", vpc=vpc,
                                           launch_template=launch_template,
                                           desired_capacity=cluster_capacity)
        capacity_provider = ecs.AsgCapacityProvider(
            self, "AsgCapacityProvider",
            auto_scaling_group=asg,
            enable_managed_termination_protection=False,
        )
        cluster.add_asg_capacity_provider(capacity_provider)

        export(self, "EcsClusterCapacity", str(cluster_capacity))
        export(self, "EcsClusterName", cluster.cluster_name)
        export(self, "EcsClusterArn", cluster.cluster_arn)

        windows_platform = ecs.RuntimePlatform(
            operating_system_family=ecs.OperatingSystemFamily.WINDOWS_SERVER_2019_FULL)
        windows_task_def = ecs.FargateTaskDefinition(
            self, "WindowsTaskDef", runtime_platform=windows_platform, cpu=1024,
            memory_limit_mib=2048)

        execution_role = iam.Role(self, "TaskExecutionRole",
                                  assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"))
        execution_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AmazonECSTaskExecutionRolePolicy"))
        windows_task_def_with_role = ecs.FargateTaskDefinition(
            self, "WindowsTaskDefWithExecutionRole", runtime_platform=windows_platform,
            cpu=1024, memory_limit_mib=2048, execution_role=execution_role)
        container_with_role = windows_task_def_with_role.add_container(
            "web", image=ecs.ContainerImage.from_registry(_IIS_IMAGE), memory_limit_mib=1024,
            cpu=512)
        container_with_role.add_port_mappings(ecs.PortMapping(container_port=80))

        gpu_task_def = ecs.Ec2TaskDefinition(self, "GpuTaskDef")
        gpu_container_name = "gpu-container"
        gpu_task_def.add_container(
            gpu_container_name,
            image=ecs.ContainerImage.from_registry("public.ecr.aws/docker/library/alpine:latest"),
            memory_limit_mib=4096,
            gpu_count=1,
        )

        export(self, "WindowsTaskDefArnWithTaskExecutionRole",
               windows_task_def_with_role.task_definition_arn)
        export(self, "WindowsTaskDefArn", windows_task_def.task_definition_arn)
        export(self, "GpuTaskDefArn", gpu_task_def.task_definition_arn)

        service = ecs.FargateService(self, "MyService", cluster=cluster,
                                     task_definition=windows_task_def, desired_count=2,
                                     assign_public_ip=False,
                                     vpc_subnets=ec2.SubnetSelection(
                                         subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS))

        container = windows_task_def.add_container(
            "web", image=ecs.ContainerImage.from_registry(_IIS_IMAGE), memory_limit_mib=1024,
            cpu=512)
        container.add_port_mappings(ecs.PortMapping(container_port=80))

        target_group = elbv2.ApplicationTargetGroup(
            self, "EcsTargetGroup", vpc=vpc, port=80,
            protocol=elbv2.ApplicationProtocol.HTTP, targets=[service])
        # open=False: the ALB's own group admits only the VPC CIDR, never any address.
        elbv2.ApplicationListener(self, "EcsListener", load_balancer=alb, port=80, open=False,
                                  default_target_groups=[target_group])

        repository = ecr.Repository(
            self, "MyEcrRepository",
            repository_name=f"{prefix}-ecr-repo",
            lifecycle_rules=[ecr.LifecycleRule(rule_priority=1,
                                               description="Keep only the last 10 images",
                                               max_image_count=10)],
            removal_policy=RemovalPolicy.DESTROY,
        )
        export(self, "EcrRepositoryUri", repository.repository_uri)

        export(self, "WindowsTaskDefFamily", windows_task_def.family)
        export(self, "GpuTaskDefFamily", gpu_task_def.family)
        export(self, "EcsServiceName", service.service_name)
        export(self, "EcsServiceArn", service.service_arn)
        export(self, "TargetGroupArn", target_group.target_group_arn)
        export(self, "TargetGroupName", target_group.target_group_name)
        export(self, "WindowsContainerName", container.container_name)
        export(self, "WindowsContainerWithExecutionRoleName", container_with_role.container_name,
               "")
        export(self, "GpuContainerName", gpu_container_name)


class ComputeEc2Stack(cdk.Stack):
    def __init__(self, scope, construct_id, *, vpc: ec2.IVpc, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        launch_template = ec2.CfnLaunchTemplate(
            self, "MyLaunchTemplate",
            launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
                instance_type=ec2.InstanceType.of(
                    ec2.InstanceClass.T3, ec2.InstanceSize.MICRO).to_string(),
                image_id=ec2.AmazonLinuxImage(
                    generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023,
                ).get_image(self).image_id,
                metadata_options=ec2.CfnLaunchTemplate.MetadataOptionsProperty(
                    http_tokens="required",
                    http_put_response_hop_limit=1,
                    http_endpoint="enabled",
                ),
            ),
        )

        instance_role = iam.Role(
            self, "Ec2InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")],
        )
        instance_profile = iam.CfnInstanceProfile(self, "InstanceProfile",
                                                  roles=[instance_role.role_name])

        instance = ec2.CfnInstance(
            self, "TestInstance",
            subnet_id=vpc.private_subnets[0].subnet_id,
            iam_instance_profile=instance_profile.ref,
            launch_template=ec2.CfnInstance.LaunchTemplateSpecificationProperty(
                launch_template_id=launch_template.ref,
                version=launch_template.attr_latest_version_number,
            ),
        )
        instance.node.add_dependency(vpc)
        Tags.of(instance).add("CreatedBy", "example-user")

        export(self, "EC2InstanceId", instance.ref)
        export(self, "LaunchTemplateId", launch_template.ref)


class DocDbAthenaNlbStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, vpc: ec2.IVpc, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        cluster = docdb.DatabaseCluster(
            self, "my-recommendation-engine",
            master_user=docdb.Login(username="dbadmin"),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            removal_policy=RemovalPolicy.DESTROY,
        )
        cluster.node.add_dependency(vpc)

        analysis_bucket = _secure_bucket(self, "athena-analytics-data-bucket")
        dynamodb.Table(
            self, "my-feature-store",
            partition_key=dynamodb.Attribute(name="featureId", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        )
        output_location = f"s3://{analysis_bucket.bucket_name}/athena-results/"
        workgroup = athena.CfnWorkGroup(
            self, "my-data-science-workgroup",
            name=f"{prefix}-data-science",
            # Queries leave the workgroup non-empty; a stack delete must still delete it.
            recursive_delete_option=True,
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=output_location),
            ),
        )

        logging_bucket = _secure_bucket(self, "InternalNLBLoggingBucket")
        nlb = elbv2.NetworkLoadBalancer(
            self, "InternalNLB",
            vpc=vpc,
            internet_facing=False,
            load_balancer_name=f"{prefix}-nlb",
            vpc_subnets=ec2.SubnetSelection(subnets=vpc.private_subnets),
        )
        nlb.log_access_logs(logging_bucket)
        # Empty the log bucket only once the load balancer writing into it is gone.
        logging_bucket.node.find_child("AutoDeleteObjectsCustomResource").node.add_dependency(nlb)

        sales_data = dynamodb.Table(
            self, "SalesDataTable",
            table_name=f"{prefix}-sales-data",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
        )

        notifications_topic = sns.Topic.from_topic_arn(
            self, "NotificationsTopic",
            # A foreign placeholder account, so the import never names a topic of this account.
            self.format_arn(service="sns", account="123456789012", resource="my-notifications"),
        )

        sales_history = dynamodb.Table(
            self, "SalesHistoryTable",
            table_name=f"{prefix}-sales-history",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
        )

        processor_log_group = logs.LogGroup(self, "DataProcessorLambdaLogGroup",
                                            removal_policy=RemovalPolicy.DESTROY)
        processor = lambda_.Function(
            self, "DataProcessorLambda",
            log_group=processor_log_group,
            runtime=lambda_.Runtime.NODEJS_20_X,
            handler="index.handler",
            code=lambda_.InlineCode(_INLINE_HANDLER),
            vpc=vpc,
        )

        sales_data.grant_read_write_data(processor)
        sales_history.grant_read_write_data(processor)
        notifications_topic.grant_publish(processor)

        export(self, "InternalNLBName", nlb.load_balancer_full_name)
        export(self, "InternalNLBAccessLoggingBucketName", logging_bucket.bucket_name)
        export(self, "DocDbClusterName", cluster.cluster_identifier)
        export(self, "DocDbClusterEndpoint", cluster.cluster_endpoint.hostname)
        export(self, "DocDbClusterArn",
               f"arn:{self.partition}:rds:{self.region}:{self.account}:cluster:"
               f"{cluster.cluster_identifier}", "")
        export(self, "DocDbSecurityGroupId",
               cluster.connections.security_groups[0].security_group_id, "")
        export(self, "AnalysisDataBucketName", analysis_bucket.bucket_name)
        export(self, "AnalysisDataBucketArn", analysis_bucket.bucket_arn)
        export(self, "AthenaWorkgroupName", workgroup.name)
        export(self, "AthenaOutputLocation", output_location, "")
        export(self, "MyDataProcessorLambda", processor.function_name)
        export(self, "MySalesDataTable", sales_data.table_name)


def build(app: cdk.App) -> None:
    """Every stack of the estate, with the networking stack ahead of each VPC consumer."""
    ctx = app.node.try_get_context
    account, region, prefix = ctx("account"), ctx("region"), ctx("prefix")
    env = cdk.Environment(account=account, region=region)

    def stack_kwargs() -> dict:
        return {"env": env,
                "synthesizer": cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier"))}

    AccessRolesStack(app, f"{prefix}-AccessRoles", prefix=prefix, **stack_kwargs())
    networking = NetworkingStack(app, f"{prefix}-Networking", **stack_kwargs())
    S3StorageStack(app, f"{prefix}-S3Storage", prefix=prefix, **stack_kwargs())
    MonitoringStack(app, f"{prefix}-Monitoring", prefix=prefix, **stack_kwargs())

    vpc = networking.vpc
    dependents = [
        DatabaseStack(app, f"{prefix}-Database", vpc=vpc, **stack_kwargs()),
        LambdaMiscStack(app, f"{prefix}-LambdaMisc", prefix=prefix, vpc=vpc, **stack_kwargs()),
        EcsStack(app, f"{prefix}-ECS", prefix=prefix, vpc=vpc, alb=networking.alb,
                 **stack_kwargs()),
        ComputeEc2Stack(app, f"{prefix}-ComputeEC2", vpc=vpc, **stack_kwargs()),
        DocDbAthenaNlbStack(app, f"{prefix}-DocDBAthenaNLB", prefix=prefix, vpc=vpc,
                            **stack_kwargs()),
    ]
    for stack in dependents:
        stack.add_dependency(networking)


app = cdk.App()
# The VPC's zone lookup is answered from context, so synth makes no AWS call.
app.node.set_context(
    f"availability-zones:account={app.node.try_get_context('account')}"
    f":region={app.node.try_get_context('region')}",
    app.node.try_get_context("azs").split(","),
)
build(app)
app.synth()
