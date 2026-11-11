#!/usr/bin/env python3
"""A three-region API and observability estate: APIs, search, warehousing, workflows and telemetry.

Twenty-three stacks across a primary, a western and a south-east Asian region: REST and WebSocket
APIs, three VPC OpenSearch domains, a Redshift cluster with a VPC-only SageMaker domain, Bedrock
knowledge bases on S3 Vectors, CloudFront distributions, ECS services behind load balancers, Step
Functions workflows, DynamoDB stream processors and SQS-driven functions. Nothing is reachable from
outside its VPC: load balancers are internal, no security group admits 0.0.0.0/0, the REST API has
no stage, the WebSocket APIs have no stage, the content distribution is disabled, every database
and search endpoint is private and tasks run without public IPs.

Context:
  account                 -- the account
  east, west, apse        -- the three regions
  azs_east/azs_west/azs_apse -- comma-separated zones per region, the answer to each VPC's lookup
  prefix                  -- stack ids are "<prefix>-<Part>"; every fixed physical name starts
                             with it
  qualifier               -- bootstrap qualifier (functions, layers and images are assets)
"""
from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Duration, RemovalPolicy
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_integrations as apigwv2_integrations
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_elasticloadbalancingv2_targets as elbv2_targets
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_glue as glue
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_event_sources as event_sources
from aws_cdk import aws_logs as logs
from aws_cdk import aws_opensearchservice as opensearch
from aws_cdk import aws_redshift as redshift
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_s3vectors as s3vectors
from aws_cdk import aws_sagemaker as sagemaker
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from aws_cdk import custom_resources as cr

_ASSETS = Path(__file__).resolve().parent / "assets"
_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
_EMBEDDING_DIMENSIONS = 1024
_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_AUTO_DELETE_PROVIDER = "Custom::S3AutoDeleteObjectsCustomResourceProvider"


def export(stack: cdk.Stack, name: str, value: str, description: str | None = None) -> None:
    """An output exported as "<stack name>-<name>"."""
    cdk.CfnOutput(stack, name, value=value, export_name=f"{stack.stack_name}-{name}",
                  description=description)


def asset(name: str) -> lambda_.Code:
    return lambda_.Code.from_asset(str(_ASSETS / name))


def bucket(scope, construct_id: str, **kwargs) -> s3.Bucket:
    """A private, TLS-only bucket deleted with its objects; SSE-S3 unless told otherwise."""
    kwargs.setdefault("encryption", s3.BucketEncryption.S3_MANAGED)
    return s3.Bucket(scope, construct_id, block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                     enforce_ssl=True, removal_policy=RemovalPolicy.DESTROY,
                     auto_delete_objects=True, **kwargs)


def harden_auto_delete(stack: cdk.Stack, buckets: list[s3.IBucket]) -> None:
    """Identity grants for the auto-delete handler, so emptying never rests on the bucket policy."""
    provider = stack.node.try_find_child(_AUTO_DELETE_PROVIDER)
    if provider is None:
        return
    resources = []
    for b in buckets:
        resources += [b.bucket_arn, f"{b.bucket_arn}/*"]
    provider.add_to_role_policy({
        "Effect": "Allow",
        "Action": ["s3:GetBucket*", "s3:List*", "s3:DeleteObject*", "s3:PutBucketPolicy"],
        "Resource": resources,
    })


def empty_after(b: s3.Bucket, writer) -> None:
    """Empty `b` on delete only once `writer` is gone: the writer depends on the auto-delete."""
    writer.node.add_dependency(b.node.find_child("AutoDeleteObjectsCustomResource"))


class AppRolesStack(cdk.Stack):
    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        vectors_read_only = iam.ManagedPolicy(
            self, "S3VectorsReadOnlyAccess",
            managed_policy_name=f"{prefix}-s3vectors-ro",
            description="Read-only access to S3 Vectors operations",
            statements=[iam.PolicyStatement(
                sid="AllowS3VectorsReadOnlyAccess",
                actions=["s3vectors:ListVectors", "s3vectors:GetVectors", "s3vectors:GetIndex",
                         "s3vectors:GetVectorBucket", "s3vectors:GetVectorBucketPolicy",
                         "s3vectors:ListIndexes", "s3vectors:ListTagsForResource",
                         "s3vectors:ListVectorBuckets", "s3vectors:QueryVectors"],
                resources=["*"],
            )],
        )
        managed = iam.ManagedPolicy.from_aws_managed_policy_name
        # The application roles read only; neither holds write or administrator access.
        iam.Role(self, "ApplicationReadOnlyRole", role_name=f"{prefix}-app-readonly",
                 assumed_by=iam.AccountPrincipal(self.account),
                 managed_policies=[managed("ReadOnlyAccess"),
                                   managed("AmazonS3TablesReadOnlyAccess"), vectors_read_only])
        iam.Role(self, "ApplicationAdminRole", role_name=f"{prefix}-app-admin",
                 assumed_by=iam.AccountPrincipal(self.account),
                 managed_policies=[managed("ReadOnlyAccess")])
        # Bedrock's service role: nothing in the estate invokes a model, so it holds no policy.
        iam.Role(self, "BedrockServiceAccessRole", role_name=f"{prefix}-bedrock-access",
                 assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"))


class TenantOnlyDistributionStack(cdk.Stack):
    """A tenant-only distribution over a bucket whose policy grants CloudFront nothing."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        bucket_name = f"{prefix}-tenant-services-{self.region}"
        tenant_bucket = s3.CfnBucket(
            self, "TenantServicesBucket",
            bucket_name=bucket_name,
            versioning_configuration=s3.CfnBucket.VersioningConfigurationProperty(status="Enabled"),
            bucket_encryption=s3.CfnBucket.BucketEncryptionProperty(
                server_side_encryption_configuration=[s3.CfnBucket.ServerSideEncryptionRuleProperty(
                    server_side_encryption_by_default=s3.CfnBucket.ServerSideEncryptionByDefaultProperty(
                        sse_algorithm="AES256"))]),
            public_access_block_configuration=s3.CfnBucket.PublicAccessBlockConfigurationProperty(
                block_public_acls=True, block_public_policy=True, ignore_public_acls=True,
                restrict_public_buckets=True),
            tags=[cdk.CfnTag(key="Name", value=bucket_name)],
        )
        tenant_bucket.apply_removal_policy(RemovalPolicy.DESTROY)
        # TLS-only, and no statement for the distribution's origin access control.
        s3.CfnBucketPolicy(self, "TenantServicesBucketPolicy", bucket=tenant_bucket.ref,
                           policy_document={
                               "Version": "2012-10-17",
                               "Statement": [{
                                   "Sid": "DenyNonSSL", "Effect": "Deny",
                                   "Principal": {"AWS": "*"}, "Action": "s3:*",
                                   "Resource": [f"arn:{self.partition}:s3:::{bucket_name}",
                                                f"arn:{self.partition}:s3:::{bucket_name}/*"],
                                   "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                               }],
                           })
        oac = cloudfront.CfnOriginAccessControl(
            self, "TenantOAC",
            origin_access_control_config=cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name=f"{prefix}-tenant-oac", origin_access_control_origin_type="s3",
                signing_behavior="always", signing_protocol="sigv4"))
        connection_group = cloudfront.CfnConnectionGroup(
            self, "TenantConnectionGroup", name=f"{prefix}-tenant-connection-group",
            enabled=True, ipv6_enabled=True)
        # Tenant-only: it serves only through distribution tenants, and the estate creates none.
        distribution = cloudfront.CfnDistribution(
            self, "MultiTenantDistribution",
            distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
                enabled=True,
                comment="Multi-tenant distribution",
                connection_mode="tenant-only",
                origins=[cloudfront.CfnDistribution.OriginProperty(
                    id="S3Origin",
                    domain_name=f"{bucket_name}.s3.{self.region}.amazonaws.com",
                    origin_path="/{{TenantPath}}",
                    origin_access_control_id=oac.attr_id,
                    s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                        origin_access_identity=""))],
                default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                    target_origin_id="S3Origin", viewer_protocol_policy="redirect-to-https",
                    allowed_methods=["GET", "HEAD"], cached_methods=["GET", "HEAD"],
                    cache_policy_id=_CACHING_OPTIMIZED, compress=True),
                http_version="http2",
                viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                    cloud_front_default_certificate=True,
                    minimum_protocol_version="TLSv1.2_2021"),
                tenant_config=cloudfront.CfnDistribution.TenantConfigProperty(
                    parameter_definitions=[cloudfront.CfnDistribution.ParameterDefinitionProperty(
                        name="TenantPath",
                        definition=cloudfront.CfnDistribution.DefinitionProperty(
                            string_schema=cloudfront.CfnDistribution.StringSchemaProperty(
                                comment="S3 keyspace prefix for this tenant", required=True)))]),
            ),
        )
        zone = route53.HostedZone(self, "TenantHostedZone", zone_name=f"{prefix}-tenant.net")

        export(self, "TenantServicesBucketName", tenant_bucket.ref)
        export(self, "DistributionId", distribution.attr_id)
        export(self, "ConnectionGroupId", connection_group.attr_id)
        export(self, "ConnectionGroupRoutingEndpoint", connection_group.attr_routing_endpoint)
        export(self, "HostedZoneId", zone.hosted_zone_id)
        export(self, "OACId", oac.attr_id)


_EFS_CLEANUP = """
import time
import boto3
import cfnresponse

NFS_GROUPS = ("security-group-for-inbound-nfs-", "security-group-for-outbound-nfs-")


def handler(event, context):
    try:
        if event["RequestType"] == "Delete":
            clean(event["ResourceProperties"]["VpcId"], context)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "home-volume-cleanup")
    except Exception as exc:
        print(repr(exc))
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, "home-volume-cleanup")


def left(context):
    return context.get_remaining_time_in_millis() / 1000.0 - 30


def mount_targets(efs, fs_id):
    try:
        return efs.describe_mount_targets(FileSystemId=fs_id)["MountTargets"]
    except efs.exceptions.FileSystemNotFound:
        return []


def clean(vpc_id, context):
    efs = boto3.client("efs")
    ec2 = boto3.client("ec2")
    for page in efs.get_paginator("describe_file_systems").paginate():
        for fs in page["FileSystems"]:
            if not any(t["Key"] == "ManagedByAmazonSageMakerResource" for t in fs.get("Tags", [])):
                continue
            fs_id = fs["FileSystemId"]
            targets = mount_targets(efs, fs_id)
            if not targets or any(t["VpcId"] != vpc_id for t in targets):
                continue
            for target in targets:
                try:
                    efs.delete_mount_target(MountTargetId=target["MountTargetId"])
                except efs.exceptions.MountTargetNotFound:
                    pass
            while mount_targets(efs, fs_id):
                if left(context) < 0:
                    raise TimeoutError(f"mount targets of {fs_id} still deleting")
                time.sleep(5)
            try:
                efs.delete_file_system(FileSystemId=fs_id)
            except efs.exceptions.FileSystemNotFound:
                pass
    groups = [
        g for g in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        if g["GroupName"].startswith(NFS_GROUPS)
    ]
    for g in groups:
        if g["IpPermissions"]:
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"],
                                              IpPermissions=g["IpPermissions"])
        if g["IpPermissionsEgress"]:
            ec2.revoke_security_group_egress(GroupId=g["GroupId"],
                                             IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        while True:
            try:
                ec2.delete_security_group(GroupId=g["GroupId"])
                break
            except ec2.exceptions.ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    break
                if code != "DependencyViolation" or left(context) < 0:
                    raise
                time.sleep(10)
"""


class RedshiftStack(cdk.Stack):
    """A private Redshift cluster and a VPC-only SageMaker domain sharing one VPC.

    The domain's security group admits the cluster port, yet the cluster does not carry it.
    """

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(
            self, "FlintVpc", vpc_name=f"{prefix}-flint-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"), max_azs=2, nat_gateways=1,
            enable_dns_hostnames=True, enable_dns_support=True,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=24, name="flint-af-pubsubnet",
                                        subnet_type=ec2.SubnetType.PUBLIC,
                                        map_public_ip_on_launch=True),
                ec2.SubnetConfiguration(cidr_mask=24, name="flint-af-privsubnet",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ],
        )
        private_a, private_b = vpc.private_subnets[0], vpc.private_subnets[1]

        def group(construct_id: str, name: str, description: str) -> ec2.SecurityGroup:
            return ec2.SecurityGroup(self, construct_id, vpc=vpc,
                                     security_group_name=f"{prefix}-{name}",
                                     description=description, allow_all_outbound=True)

        sg_redshift_sagemaker = group("SgRedshiftSagemaker", "vpc-internal-sg",
                                      "Security group for internal VPC connectivity")
        sg_redshift_sagemaker.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(8192),
                                               "Allow Redshift port from VPC")
        sg_allow_prod_corp = group("SgAllowProdCorp", "allow-prod-corp-port-8192-8200",
                                   "Allow PROD and CORP traffic on port 8192-8200")
        sg_prod_ranges = group("SgProdRanges", "prod-ranges", "Prod Ranges")
        for sg in (sg_allow_prod_corp, sg_prod_ranges):
            sg.add_ingress_rule(ec2.Peer.ipv4("172.31.16.0/23"), ec2.Port.tcp_range(8192, 8200),
                                "Allow from CORP range 1")
            sg.add_ingress_rule(ec2.Peer.ipv4("172.31.0.0/20"), ec2.Port.tcp_range(8192, 8200),
                                "Allow from CORP range 2")
        sg_default = group("SgDefault", "default-sg", "default VPC security group")
        sg_default.add_ingress_rule(sg_default, ec2.Port.all_traffic(),
                                    "Allow self-referencing traffic")
        sg_vpc_endpoint = group("SgVpcEndpoint", "vpc-endpoint-sg",
                                "Security group for VPC endpoints")
        sg_vpc_endpoint.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(443),
                                         "Allow HTTPS from VPC")

        key = kms.Key(self, "RedshiftKmsKey", alias=f"{prefix}-flint-redshift",
                      description="KMS key for Redshift cluster encryption",
                      enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)
        parameter_group = redshift.CfnClusterParameterGroup(
            self, "RedshiftParameterGroup",
            description="Parameter group for flint-forecast cluster",
            parameter_group_family="redshift-1.0",
            parameters=[redshift.CfnClusterParameterGroup.ParameterProperty(
                parameter_name="require_ssl", parameter_value="true")])
        subnet_group = redshift.CfnClusterSubnetGroup(
            self, "RedshiftSubnetGroup", description="Subnet group for flint-forecast cluster",
            subnet_ids=[private_a.subnet_id, private_b.subnet_id],
            tags=[cdk.CfnTag(key="Name", value=f"{prefix}-flint-af-subnet-group")])
        managed = iam.ManagedPolicy.from_aws_managed_policy_name
        glue_role = iam.Role(self, "RedshiftGlueRole", role_name=f"{prefix}-flint-glue",
                             assumed_by=iam.ServicePrincipal("redshift.amazonaws.com"),
                             managed_policies=[managed("AmazonS3ReadOnlyAccess")])
        # The cluster runs no COPY or UNLOAD, so the role it would use for them holds no policy.
        copy_unload_role = iam.Role(self, "RedshiftCopyUnloadRole",
                                    role_name=f"{prefix}-redshift-copy-unload",
                                    assumed_by=iam.ServicePrincipal("redshift.amazonaws.com"))
        cluster = redshift.CfnCluster(
            self, "RedshiftCluster",
            cluster_type="single-node", node_type="ra3.large", db_name="flintforecast",
            master_username="flintadmin",
            cluster_identifier=f"{prefix}-flint-forecast",
            cluster_subnet_group_name=subnet_group.attr_cluster_subnet_group_name,
            vpc_security_group_ids=[sg_allow_prod_corp.security_group_id,
                                    sg_prod_ranges.security_group_id,
                                    sg_default.security_group_id,
                                    sg_vpc_endpoint.security_group_id],
            cluster_parameter_group_name=parameter_group.ref,
            encrypted=True, kms_key_id=key.key_arn, publicly_accessible=False,
            enhanced_vpc_routing=False, automated_snapshot_retention_period=1, port=8192,
            iam_roles=[glue_role.role_arn, copy_unload_role.role_arn],
        )
        # Redshift keeps the admin password in a secret of its own; none is written here.
        cluster.add_property_override("ManageMasterPassword", True)
        cluster.apply_removal_policy(RemovalPolicy.DESTROY)
        cluster.add_dependency(parameter_group)
        cluster.add_dependency(subnet_group)

        # No user profile, app or job runs in the domain, so its execution role holds no policy.
        execution_role = iam.Role(self, "SagemakerExecutionRole",
                                  role_name=f"{prefix}-sagemaker-exec",
                                  assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"))

        # The domain keeps its home EFS volume, mount targets and NFS groups when deleted, and they
        # hold the VPC. This resource sits between the two: deleted after the domain, it removes
        # them before the subnets go.
        cleanup_fn = lambda_.Function(
            self, "HomeVolumeCleanupFunction",
            runtime=lambda_.Runtime.PYTHON_3_12, handler="index.handler",
            code=lambda_.Code.from_inline(_EFS_CLEANUP), timeout=Duration.minutes(15),
            description="Removes the domain's home volume and NFS groups from its VPC on delete",
        )
        cleanup_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["elasticfilesystem:DescribeFileSystems",
                     "elasticfilesystem:DescribeMountTargets",
                     "elasticfilesystem:DeleteMountTarget",
                     "elasticfilesystem:DeleteFileSystem",
                     "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"],
            resources=["*"]))
        cleanup_fn.add_to_role_policy(iam.PolicyStatement(
            actions=["ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
                     "ec2:DeleteSecurityGroup", "ec2:DeleteNetworkInterface"],
            resources=["*"],
            conditions={"ArnEquals": {"ec2:Vpc": self.format_arn(
                service="ec2", resource="vpc", resource_name=vpc.vpc_id)}}))
        home_volume_cleanup = cdk.CustomResource(
            self, "HomeVolumeCleanup", service_token=cleanup_fn.function_arn,
            properties={"VpcId": vpc.vpc_id})
        home_volume_cleanup.node.add_dependency(vpc)

        domain = sagemaker.CfnDomain(
            self, "SagemakerDomain",
            domain_name=f"{prefix}-flint-forecast",
            auth_mode="IAM", vpc_id=vpc.vpc_id,
            subnet_ids=[private_a.subnet_id, private_b.subnet_id],
            app_network_access_type="VpcOnly",
            default_user_settings=sagemaker.CfnDomain.UserSettingsProperty(
                execution_role=execution_role.role_arn,
                security_groups=[sg_redshift_sagemaker.security_group_id]),
            domain_settings=sagemaker.CfnDomain.DomainSettingsProperty(
                security_group_ids=[sg_allow_prod_corp.security_group_id,
                                    sg_prod_ranges.security_group_id,
                                    sg_default.security_group_id]),
        )
        domain.node.add_dependency(home_volume_cleanup)

        endpoint = ec2.InterfaceVpcEndpoint(
            self, "SecretsManagerEndpoint", vpc=vpc,
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            subnets=ec2.SubnetSelection(subnets=[private_a, private_b]),
            security_groups=[sg_vpc_endpoint, sg_allow_prod_corp, sg_default],
            private_dns_enabled=True)

        export(self, "VpcId", vpc.vpc_id)
        export(self, "PrivateSubnet1aId", private_a.subnet_id)
        export(self, "PrivateSubnet1bId", private_b.subnet_id)
        export(self, "SgRedshiftSagemakerId", sg_redshift_sagemaker.security_group_id)
        export(self, "SgAllowProdCorpId", sg_allow_prod_corp.security_group_id)
        export(self, "SgProdRangesId", sg_prod_ranges.security_group_id)
        export(self, "SgDefaultId", sg_default.security_group_id)
        export(self, "SgVpcEndpointId", sg_vpc_endpoint.security_group_id)
        export(self, "RedshiftClusterIdentifier", cluster.ref)
        export(self, "RedshiftClusterEndpoint", cluster.attr_endpoint_address)
        export(self, "RedshiftClusterPort", cluster.attr_endpoint_port)
        export(self, "RedshiftKmsKeyArn", key.key_arn)
        export(self, "SagemakerDomainId", domain.attr_domain_id)
        export(self, "SagemakerDomainArn", domain.attr_domain_arn)
        export(self, "SagemakerExecutionRoleArn", execution_role.role_arn)
        export(self, "SecretsManagerEndpointId", endpoint.vpc_endpoint_id)


class OrchestratorStack(cdk.Stack):
    """A state machine whose role may write its logs but may not invoke the function it names."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        log_group = logs.LogGroup(self, "StepFunctionsLogGroup",
                                  log_group_name=f"/aws/vendedlogs/states/{prefix}-danube",
                                  retention=logs.RetentionDays.ONE_YEAR,
                                  removal_policy=RemovalPolicy.DESTROY)
        role = iam.Role(self, "StateMachineRole", role_name=f"{prefix}-danube-sfn",
                        assumed_by=iam.ServicePrincipal("states.amazonaws.com"))
        role.add_to_policy(iam.PolicyStatement(
            actions=["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
                     "logs:DeleteLogDelivery", "logs:ListLogDeliveries",
                     "logs:PutResourcePolicy", "logs:DescribeResourcePolicies",
                     "logs:DescribeLogGroups"],
            resources=["*"]))
        name = f"{prefix}-danube-orchestrator"
        definition = {
            "Comment": "Job orchestration workflow",
            "StartAt": "ProcessJob",
            "States": {
                "ProcessJob": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::lambda:invoke",
                    "Parameters": {"FunctionName": f"{prefix}-job-processor", "Payload.$": "$"},
                    "ResultPath": "$.jobResult",
                    "Next": "CheckResult",
                    "Catch": [{"ErrorEquals": ["States.ALL"], "Next": "JobFailed"}],
                },
                "CheckResult": {
                    "Type": "Choice",
                    "Choices": [{"Variable": "$.jobResult.status", "StringEquals": "SUCCESS",
                                 "Next": "JobSucceeded"}],
                    "Default": "JobFailed",
                },
                "JobSucceeded": {"Type": "Succeed"},
                "JobFailed": {"Type": "Fail", "Error": "JobProcessingFailed",
                              "Cause": "Job processing did not complete successfully"},
            },
        }
        machine = sfn.StateMachine(
            self, "OrchestratorStateMachine", state_machine_name=name,
            definition_body=sfn.DefinitionBody.from_string(cdk.Stack.of(self).to_json_string(
                definition)),
            role=role, state_machine_type=sfn.StateMachineType.STANDARD,
            logs=sfn.LogOptions(destination=log_group, level=sfn.LogLevel.ALL,
                                include_execution_data=True))
        export(self, "StateMachineArn", machine.state_machine_arn)
        export(self, "StateMachineName", name)
        export(self, "StepFunctionsLogGroupName", log_group.log_group_name)


class OpenSearchSlrStack(cdk.Stack):
    """Ensures OpenSearch's service-linked role exists; the account-wide role outlives the stack."""

    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        cr.AwsCustomResource(
            self, "OpenSearchSLR",
            on_create=cr.AwsSdkCall(
                service="IAM", action="createServiceLinkedRole",
                parameters={"AWSServiceName": "opensearchservice.amazonaws.com"},
                ignore_error_codes_matching="InvalidInput",
                physical_resource_id=cr.PhysicalResourceId.of("OpenSearchServiceLinkedRole")),
            install_latest_aws_sdk=False,
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE),
        )


class CognitoSearchStack(cdk.Stack):
    """A VPC domain with Cognito dashboard sign-in and an internal ALB with an empty group."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(
            self, "Vpc", vpc_name=f"{prefix}-basalt-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"), max_azs=2, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=20, name="Public",
                                        subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=20, name="Private",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ],
        )
        search_sg = ec2.SecurityGroup(self, "OpenSearchSg", vpc=vpc,
                                      security_group_name=f"{prefix}-basalt-opensearch",
                                      description="Security group for OpenSearch domain",
                                      allow_all_outbound=True)
        search_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(443),
                                   "Allow HTTPS from VPC")
        alb_sg = ec2.SecurityGroup(self, "AlbSg", vpc=vpc,
                                   security_group_name=f"{prefix}-basalt-alb",
                                   description="Security group for ALB", allow_all_outbound=True)
        alb_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/8"), ec2.Port.tcp(443),
                                "Allow HTTPS from corporate network")
        key = kms.Key(self, "KmsKey", alias=f"alias/{prefix}-basalt-opensearch",
                      description="KMS key for OpenSearch encryption at rest",
                      enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)
        user_pool = cognito.UserPool(
            self, "UserPool", user_pool_name=f"{prefix}-basalt-user-pool",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True, username=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            standard_attributes=cognito.StandardAttributes(
                email=cognito.StandardAttribute(required=True, mutable=True)),
            removal_policy=RemovalPolicy.DESTROY)
        user_pool.add_domain("UserPoolDomain", cognito_domain=cognito.CognitoDomainOptions(
            domain_prefix=f"{prefix}-basalt-auth"))
        alb = elbv2.ApplicationLoadBalancer(
            self, "Alb", load_balancer_name=f"{prefix}-basalt-alb", vpc=vpc,
            internet_facing=False, security_group=alb_sg,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS))
        client = cognito.UserPoolClient(
            self, "UserPoolClient", user_pool=user_pool,
            user_pool_client_name=f"{prefix}-basalt-client", generate_secret=False,
            # Admin password sign-in on top of the default flows, so a user's sign-in can be
            # exercised server-side against the pool the dashboards use.
            auth_flows=cognito.AuthFlow(admin_user_password=True, user_srp=True, custom=True),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True, implicit_code_grant=True),
                scopes=[cognito.OAuthScope.EMAIL, cognito.OAuthScope.OPENID,
                        cognito.OAuthScope.PROFILE],
                callback_urls=[f"https://{alb.load_balancer_dns_name}/_dashboards/app/home"]),
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.COGNITO],
            refresh_token_validity=Duration.days(30))
        identity_pool = cognito.CfnIdentityPool(
            self, "IdentityPool",
            identity_pool_name=f"{prefix.replace('-', '_')}_basalt_identity_pool",
            allow_unauthenticated_identities=False,
            cognito_identity_providers=[cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
                client_id=client.user_pool_client_id,
                provider_name=user_pool.user_pool_provider_name)])
        cognito_access_role = iam.Role(
            self, "CognitoAccessRole", role_name=f"{prefix}-basalt-cognito-access",
            assumed_by=iam.ServicePrincipal("es.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonOpenSearchServiceCognitoAccess")])
        authenticated_role = iam.Role(
            self, "AuthenticatedRole", role_name=f"{prefix}-basalt-cognito-auth",
            assumed_by=iam.FederatedPrincipal(
                "cognito-identity.amazonaws.com",
                {"StringEquals": {"cognito-identity.amazonaws.com:aud": identity_pool.ref},
                 "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"}},
                "sts:AssumeRoleWithWebIdentity"))
        cognito.CfnIdentityPoolRoleAttachment(
            self, "IdentityPoolRoleAttachment", identity_pool_id=identity_pool.ref,
            roles={"authenticated": authenticated_role.role_arn})
        domain = opensearch.Domain(
            self, "Domain", domain_name=f"{prefix}-basalt",
            version=opensearch.EngineVersion.OPENSEARCH_2_11,
            capacity=opensearch.CapacityConfig(data_nodes=1,
                                               data_node_instance_type="t3.small.search"),
            ebs=opensearch.EbsOptions(enabled=True, volume_size=10,
                                      volume_type=ec2.EbsDeviceVolumeType.GP3, iops=3000,
                                      throughput=125),
            vpc=vpc, vpc_subnets=[ec2.SubnetSelection(subnets=vpc.private_subnets[:1])],
            security_groups=[search_sg],
            encryption_at_rest=opensearch.EncryptionAtRestOptions(enabled=True, kms_key=key),
            node_to_node_encryption=True, enforce_https=True,
            tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2,
            cognito_dashboards_auth=opensearch.CognitoOptions(
                role=cognito_access_role, identity_pool_id=identity_pool.ref,
                user_pool_id=user_pool.user_pool_id),
            access_policies=[iam.PolicyStatement(
                principals=[iam.AnyPrincipal()], actions=["es:*"], resources=["*"],
                conditions={"StringEquals": {"aws:PrincipalAccount": cdk.Aws.ACCOUNT_ID}})],
            removal_policy=RemovalPolicy.DESTROY)
        target_group = elbv2.ApplicationTargetGroup(
            self, "TargetGroup", target_group_name=f"{prefix}-basalt-tg", vpc=vpc, port=443,
            protocol=elbv2.ApplicationProtocol.HTTPS, target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(enabled=True, protocol=elbv2.Protocol.HTTPS,
                                           port="443", path="/", healthy_threshold_count=2,
                                           unhealthy_threshold_count=5,
                                           healthy_http_codes="200,302"))

        export(self, "VpcId", vpc.vpc_id)
        export(self, "OpenSearchDomainName", domain.domain_name)
        export(self, "OpenSearchDomainEndpoint", domain.domain_endpoint)
        export(self, "OpenSearchDomainArn", domain.domain_arn)
        export(self, "UserPoolId", user_pool.user_pool_id)
        export(self, "UserPoolClientId", client.user_pool_client_id)
        export(self, "IdentityPoolId", identity_pool.ref)
        export(self, "AuthenticatedRoleArn", authenticated_role.role_arn)
        export(self, "AlbDnsName", alb.load_balancer_dns_name)
        export(self, "AlbArn", alb.load_balancer_arn)
        export(self, "TargetGroupArn", target_group.target_group_arn)


class KnowledgeBaseStack(cdk.Stack):
    """Two knowledge bases, each on its own S3 Vectors index, with seeded source buckets."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        metadata_data = bucket(self, "MetadataDataBucket",
                               bucket_name=f"{prefix}-kb-metadata-data-{self.region}")
        escalation_data = bucket(self, "EscalationDataBucket",
                                 bucket_name=f"{prefix}-kb-escalation-data-{self.region}")
        harden_auto_delete(self, [metadata_data, escalation_data])
        seeds = (
            ("SeedMetadataDoc", metadata_data, "metadata.txt",
             "Flint metadata knowledge base: business contexts, terminologies, data structures "
             "for metric analysis and order processing."),
            ("SeedEscalationDoc", escalation_data, "escalation.txt",
             "Flint escalation knowledge base: writeups and escalation procedures for PR review "
             "workflows."),
        )
        for construct_id_, target, key, body in seeds:
            seed = cr.AwsCustomResource(
                self, construct_id_,
                on_create=cr.AwsSdkCall(
                    service="S3", action="putObject",
                    parameters={"Bucket": target.bucket_name, "Key": key, "Body": body,
                                "ContentType": "text/plain"},
                    physical_resource_id=cr.PhysicalResourceId.of(construct_id_)),
                install_latest_aws_sdk=False,
                policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                    resources=[f"{target.bucket_arn}/*"]))
            empty_after(target, seed)

        def vector_store(construct_id_: str, name: str, index_name: str):
            vector_bucket = s3vectors.CfnVectorBucket(self, f"{construct_id_}VectorBucket",
                                                      vector_bucket_name=name)
            vector_bucket.apply_removal_policy(RemovalPolicy.DESTROY)
            index = s3vectors.CfnIndex(self, f"{construct_id_}VectorIndex",
                                       vector_bucket_name=name, index_name=index_name,
                                       data_type="float32", dimension=_EMBEDDING_DIMENSIONS,
                                       distance_metric="cosine")
            index.apply_removal_policy(RemovalPolicy.DESTROY)
            index.add_dependency(vector_bucket)
            return vector_bucket, index

        metadata_vectors, metadata_index = vector_store(
            "Metadata", f"{prefix}-kb-metadata-vectors", "metadata-index")
        escalation_vectors, escalation_index = vector_store(
            "Escalation", f"{prefix}-kb-escalation-vectors", "escalation-index")

        model_arn = (f"arn:{self.partition}:bedrock:{self.region}::foundation-model/"
                     f"{_EMBEDDING_MODEL}")
        kb_role = iam.Role(
            self, "KBRole", role_name=f"{prefix}-flint-kb",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com", conditions={
                "StringEquals": {"aws:SourceAccount": self.account},
                "ArnLike": {"aws:SourceArn":
                            f"arn:{self.partition}:bedrock:{self.region}:{self.account}:"
                            f"knowledge-base/*"},
            }))
        kb_role.add_to_policy(iam.PolicyStatement(actions=["bedrock:InvokeModel"],
                                                  resources=[model_arn]))
        kb_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=[metadata_data.bucket_arn, f"{metadata_data.bucket_arn}/*",
                       escalation_data.bucket_arn, f"{escalation_data.bucket_arn}/*"]))
        kb_role.add_to_policy(iam.PolicyStatement(
            actions=["s3vectors:GetIndex", "s3vectors:PutVectors", "s3vectors:GetVectors",
                     "s3vectors:DeleteVectors", "s3vectors:QueryVectors",
                     "s3vectors:ListVectors"],
            resources=["*"]))

        def knowledge_base(construct_id_, name, description, vector_bucket, index, index_name):
            kb = bedrock.CfnKnowledgeBase(
                self, construct_id_, name=name, description=description,
                role_arn=kb_role.role_arn,
                knowledge_base_configuration=bedrock.CfnKnowledgeBase.KnowledgeBaseConfigurationProperty(
                    type="VECTOR",
                    vector_knowledge_base_configuration=bedrock.CfnKnowledgeBase.VectorKnowledgeBaseConfigurationProperty(
                        embedding_model_arn=model_arn)),
                storage_configuration=bedrock.CfnKnowledgeBase.StorageConfigurationProperty(
                    type="S3_VECTORS",
                    s3_vectors_configuration=bedrock.CfnKnowledgeBase.S3VectorsConfigurationProperty(
                        vector_bucket_arn=vector_bucket.attr_vector_bucket_arn,
                        index_name=index_name)))
            kb.add_dependency(index)
            kb.node.add_dependency(kb_role)
            return kb

        metadata_kb = knowledge_base(
            "MetadataKB", f"{prefix}-metadata-kb",
            "Comprehensive knowledge base covering business contexts, terminologies, data "
            "structures for in-depth metric analysis, order processing and customer journey "
            "investigations.",
            metadata_vectors, metadata_index, "metadata-index")
        escalation_kb = knowledge_base(
            "EscalationKB", f"{prefix}-escalation-kb",
            "Writeups and escalation procedures for PR review workflows.",
            escalation_vectors, escalation_index, "escalation-index")
        ssm.StringParameter(self, "MetadataKBParam",
                            parameter_name=f"/{prefix}/flint/beta/kb/metadata",
                            string_value=metadata_kb.attr_knowledge_base_id,
                            description="Metadata Knowledge Base ID")
        ssm.StringParameter(self, "EscalationKBParam",
                            parameter_name=f"/{prefix}/flint/beta/kb/escalation",
                            string_value=escalation_kb.attr_knowledge_base_id,
                            description="Escalation Knowledge Base ID")

        export(self, "EscalationWriteupsKBKnowledgeBaseId", escalation_kb.attr_knowledge_base_id)
        export(self, "MetadataKBKnowledgeBaseId", metadata_kb.attr_knowledge_base_id)
        export(self, "MetadataVectorBucketName", f"{prefix}-kb-metadata-vectors")
        export(self, "MetadataDataBucketName", metadata_data.bucket_name)


class AssistantConfigStack(cdk.Stack):
    """The Bedrock execution role, a session bucket and a parameter naming both knowledge bases."""

    def __init__(self, scope, construct_id, *, prefix: str, kb_stack_name: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        sessions = bucket(self, "SessionArtifactsBucket")
        role = iam.Role(
            self, "BedrockExecutionRole", role_name=f"{prefix}-bedrock-exec",
            # Only Bedrock acting for this account's own agents may assume it.
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com", conditions={
                "StringEquals": {"aws:SourceAccount": self.account},
                "ArnLike": {"aws:SourceArn":
                            f"arn:{self.partition}:bedrock:{self.region}:{self.account}:agent/*"},
            }))
        # No agent is created, so the role only reads: the session bucket and the knowledge bases.
        arn = f"arn:{self.partition}"
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"],
            resources=[sessions.bucket_arn, f"{sessions.bucket_arn}/*"]))
        role.add_to_policy(iam.PolicyStatement(
            actions=["bedrock:Retrieve"],
            resources=[f"{arn}:bedrock:{self.region}:{self.account}:knowledge-base/*"]))
        # Named imports, so the knowledge-base stack cannot be deleted while this one reads it.
        metadata_kb = cdk.Fn.import_value(f"{kb_stack_name}-MetadataKBKnowledgeBaseId")
        escalation_kb = cdk.Fn.import_value(f"{kb_stack_name}-EscalationWriteupsKBKnowledgeBaseId")
        param = ssm.StringParameter(
            self, "AssistantConfigParam",
            parameter_name=f"/{prefix}/flint/beta/pr-escalation-config",
            string_value=cdk.Fn.join("", [
                f'{{"agentName":"{prefix}-pr-escalation","description":"pr-escalation",'
                '"foundationModel":"anthropic.claude-3-sonnet-20240229-v1:0",'
                '"knowledgeBases":[{"knowledgeBaseId":"',
                metadata_kb,
                '","description":"Comprehensive knowledge base covering business contexts, '
                'terminologies, data structures for in-depth metric analysis, order processing '
                '& customer journey investigations."},{"knowledgeBaseId":"',
                escalation_kb,
                '","description":"Writeups"}]}',
            ]),
            description="Assistant configuration with knowledge base references")
        export(self, "ExecutionRoleArn", role.role_arn)
        export(self, "SessionArtifactsBucketName", sessions.bucket_name)
        export(self, "ConfigParamName", param.parameter_name)


class QuartzNlbStack(cdk.Stack):
    """An internal NLB with a management listener, an unused web group and an idle cluster."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(
            self, "QuartzVpc", vpc_name=f"{prefix}-quartz-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"), max_azs=2, nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=24, name="Public",
                                        subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=24, name="Private",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ],
        )
        sg = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc,
                               security_group_name=f"{prefix}-quartz-ecs",
                               description="Security group for QuartzWebService ECS tasks",
                               allow_all_outbound=True)
        # Both service ports admit the VPC only, never any address.
        sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(8080),
                            "Allow HTTP traffic on port 8080")
        sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(9090),
                            "Allow management API traffic on port 9090")
        cluster = ecs.Cluster(self, "QuartzWebServiceCluster",
                              cluster_name=f"{prefix}-quartz-web", vpc=vpc)
        nlb = elbv2.NetworkLoadBalancer(
            self, "NetworkLoadBalancer", load_balancer_name=f"{prefix}-quartz-nlb", vpc=vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS))
        web_group = elbv2.NetworkTargetGroup(
            self, "TargetGroup", target_group_name=f"{prefix}-quartz-web", vpc=vpc, port=8080,
            protocol=elbv2.Protocol.TCP, target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(enabled=True, protocol=elbv2.Protocol.HTTP,
                                           port="traffic-port", path="/ping",
                                           interval=Duration.seconds(30),
                                           timeout=Duration.seconds(5),
                                           healthy_threshold_count=5,
                                           unhealthy_threshold_count=2),
            deregistration_delay=Duration.seconds(300))
        mgmt_group = elbv2.NetworkTargetGroup(
            self, "MgmtTargetGroup", target_group_name=f"{prefix}-quartz-mgmt", vpc=vpc,
            port=9090, protocol=elbv2.Protocol.TCP, target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(enabled=True, protocol=elbv2.Protocol.HTTP,
                                           port="traffic-port", path="/health",
                                           interval=Duration.seconds(30),
                                           timeout=Duration.seconds(5),
                                           healthy_threshold_count=3,
                                           unhealthy_threshold_count=2))
        nlb.add_listener("MgmtListener", port=9090, protocol=elbv2.Protocol.TCP,
                         default_target_groups=[mgmt_group])

        export(self, "NetworkLoadBalancerArn", nlb.load_balancer_arn)
        export(self, "TargetGroupArn", web_group.target_group_arn)
        export(self, "SecurityGroupId", sg.security_group_id)
        export(self, "ClusterName", cluster.cluster_name)
        export(self, "NLBDNS", nlb.load_balancer_dns_name)
        export(self, "VpcId", vpc.vpc_id)
        export(self, "VpcCidr", vpc.vpc_cidr_block)
        export(self, "TargetGroupName", web_group.target_group_name)
        export(self, "MgmtTargetGroupArn", mgmt_group.target_group_arn)


class MainVpcStack(cdk.Stack):
    """A VPC with two public subnets and nothing in them."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(
            self, "MainVpc", vpc_name=f"{prefix}-main-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"), max_azs=2, nat_gateways=0,
            subnet_configuration=[ec2.SubnetConfiguration(cidr_mask=24, name="public",
                                                          subnet_type=ec2.SubnetType.PUBLIC)])
        export(self, "VpcId", vpc.vpc_id)
        export(self, "PublicSubnet1Id", vpc.public_subnets[0].subnet_id)
        export(self, "PublicSubnet2Id", vpc.public_subnets[1].subnet_id)


class AuditedSearchStack(cdk.Stack):
    """A fine-grained-access domain publishing audit, application and slow logs, with indexers."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        domain_name = f"{prefix}-flint"

        def log_group(construct_id_: str, name: str, retention) -> logs.LogGroup:
            return logs.LogGroup(self, construct_id_, log_group_name=name, retention=retention,
                                 removal_policy=RemovalPolicy.DESTROY)

        ten_years = logs.RetentionDays.TEN_YEARS
        audit = log_group("AuditLogGroup", f"/aws/opensearch/domains/{domain_name}/audit-logs",
                          ten_years)
        app_logs = log_group("AppLogGroup", f"{prefix}-app-opensearch-logs", ten_years)
        slow_index = log_group("SlowIndexLogGroup", f"{prefix}-slow-index-opensearch-logs",
                               ten_years)
        slow_search = log_group("SlowSearchLogGroup", f"{prefix}-slow-search-opensearch-logs",
                                ten_years)
        rw_role = iam.Role(
            self, "OpenSearchReadWriteRole", role_name=f"{prefix}-opensearch-rw",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="IAM role used to access OpenSearch domain with read/write permissions")
        # The domain's endpoint is private: it lives in isolated subnets of a VPC of its own.
        vpc = ec2.Vpc(
            self, "SearchVpc", vpc_name=f"{prefix}-flint-search-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.30.0.0/16"), max_azs=2, nat_gateways=0,
            subnet_configuration=[ec2.SubnetConfiguration(
                cidr_mask=24, name="Isolated", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)])
        domain = opensearch.Domain(
            self, "FlintDomain", domain_name=domain_name,
            version=opensearch.EngineVersion.OPENSEARCH_2_11,
            capacity=opensearch.CapacityConfig(data_nodes=1,
                                               data_node_instance_type="t3.small.search"),
            ebs=opensearch.EbsOptions(enabled=True, volume_size=10),
            vpc=vpc, vpc_subnets=[ec2.SubnetSelection(subnets=vpc.isolated_subnets[:1])],
            logging=opensearch.LoggingOptions(
                audit_log_enabled=True, audit_log_group=audit,
                app_log_enabled=True, app_log_group=app_logs,
                slow_index_log_enabled=True, slow_index_log_group=slow_index,
                slow_search_log_enabled=True, slow_search_log_group=slow_search),
            fine_grained_access_control=opensearch.AdvancedSecurityOptions(
                master_user_arn=rw_role.role_arn),
            node_to_node_encryption=True,
            encryption_at_rest=opensearch.EncryptionAtRestOptions(enabled=True),
            enforce_https=True,
            access_policies=[iam.PolicyStatement(actions=["es:*"], principals=[rw_role],
                                                 resources=["*"])],
            removal_policy=RemovalPolicy.DESTROY)
        rw_role.add_to_policy(iam.PolicyStatement(
            actions=["es:ESHttpGet", "es:ESHttpPut", "es:ESHttpPost", "es:ESHttpDelete"],
            resources=[domain.domain_arn, f"{domain.domain_arn}/*"]))

        def indexer(construct_id_: str, name: str) -> tuple[lambda_.Function, logs.LogGroup]:
            group = log_group(f"{construct_id_}LogGroup", f"/aws/lambda/{name}",
                              logs.RetentionDays.ONE_WEEK)
            fn = lambda_.Function(
                self, construct_id_, function_name=name, runtime=lambda_.Runtime.NODEJS_18_X,
                handler="index.handler",
                code=lambda_.Code.from_inline(
                    "exports.handler = async () => ({ statusCode: 200 });"),
                timeout=Duration.seconds(30), memory_size=256,
                environment={"OPENSEARCH_ENDPOINT": domain.domain_endpoint,
                             "INDEX_NAME": "changesets"})
            fn.node.add_dependency(group)
            domain.grant_read_write(fn)
            return fn, group

        flint_fn, flint_logs = indexer("FlintIndexerLambda", f"{prefix}-flint-indexer")
        basalt_fn, basalt_logs = indexer("BasaltFlintIndexerLambda",
                                         f"{prefix}-basalt-flint-indexer")

        export(self, "OpenSearchDomainName", domain.domain_name)
        export(self, "OpenSearchDomainEndpoint", domain.domain_endpoint)
        export(self, "OpenSearchDomainArn", domain.domain_arn)
        export(self, "AuditLogGroupName", audit.log_group_name)
        export(self, "AuditLogGroupArn", audit.log_group_arn)
        export(self, "AppLogGroupName", app_logs.log_group_name)
        export(self, "SlowIndexLogGroupName", slow_index.log_group_name)
        export(self, "SlowSearchLogGroupName", slow_search.log_group_name)
        export(self, "FlintIndexerLambdaName", flint_fn.function_name)
        export(self, "FlintIndexerLogGroupName", flint_logs.log_group_name)
        export(self, "BasaltFlintIndexerLambdaName", basalt_fn.function_name)
        export(self, "BasaltFlintIndexerLogGroupName", basalt_logs.log_group_name)
        export(self, "OpenSearchReadWriteRoleArn", rw_role.role_arn)


class WebSocketStack(cdk.Stack):
    """A WebSocket API (L2) routing every route to one handler; it has no stage."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        def table(construct_id_: str, name: str, key: str) -> dynamodb.Table:
            return dynamodb.Table(self, construct_id_, table_name=f"{prefix}-{name}",
                                  partition_key=dynamodb.Attribute(
                                      name=key, type=dynamodb.AttributeType.STRING),
                                  billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                  removal_policy=RemovalPolicy.DESTROY)

        connections = table("ConnectionsTable", "flint-websocket-connections", "connectionId")
        nodes = table("NodesTable", "flint-nodes", "nodeId")
        deployments = table("DeploymentsTable", "flint-deployments", "deploymentId")
        name = f"{prefix}-flint-message"
        log_group = logs.LogGroup(self, "LambdaLogGroup", log_group_name=f"/aws/lambda/{name}",
                                  retention=logs.RetentionDays.ONE_WEEK,
                                  removal_policy=RemovalPolicy.DESTROY)
        role = iam.Role(self, "LambdaExecutionRole",
                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                            "service-role/AWSLambdaBasicExecutionRole")])
        for t in (connections, nodes, deployments):
            t.grant_read_write_data(role)
        handler = lambda_.Function(
            self, "MessageLambda", function_name=name, runtime=lambda_.Runtime.NODEJS_18_X,
            handler="message.handler", code=asset("message-handler"),
            timeout=Duration.seconds(30), memory_size=128, role=role, log_group=log_group,
            environment={"CONNECTIONS_TABLE_NAME": connections.table_name,
                         "NODES_TABLE": nodes.table_name,
                         "DEPLOYMENTS_TABLE": deployments.table_name})
        integration = apigwv2_integrations.WebSocketLambdaIntegration
        api = apigwv2.WebSocketApi(
            self, "WebSocketApi", api_name=f"{prefix}-flint-websocket-api",
            route_selection_expression="$request.body.action",
            connect_route_options=apigwv2.WebSocketRouteOptions(
                integration=integration("ConnectIntegration", handler)),
            disconnect_route_options=apigwv2.WebSocketRouteOptions(
                integration=integration("DisconnectIntegration", handler)),
            default_route_options=apigwv2.WebSocketRouteOptions(
                integration=integration("DefaultIntegration", handler)))
        role.add_to_policy(iam.PolicyStatement(
            actions=["execute-api:ManageConnections"],
            resources=[f"arn:{self.partition}:execute-api:{self.region}:{self.account}:"
                       f"{api.api_id}/*"]))

        export(self, "WebSocketApiId", api.api_id)
        export(self, "LambdaFunctionName", handler.function_name)
        export(self, "LambdaFunctionArn", handler.function_arn)
        export(self, "ConnectionsTableName", connections.table_name)
        export(self, "NodesTableName", nodes.table_name)
        export(self, "DeploymentsTableName", deployments.table_name)
        export(self, "LogGroupName", log_group.log_group_name)


class TigrisServiceStack(cdk.Stack):
    """A Fargate API behind an internal ALB, a client service calling it, and an ALB log table."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        alb_logs = bucket(self, "ALBLogsBucket", bucket_name=f"{prefix}-tigris-logs",
                          versioned=False,
                          lifecycle_rules=[s3.LifecycleRule(id="ExpireOldLogs", enabled=True,
                                                            expiration=Duration.days(90))])
        athena_results = bucket(self, "AthenaResultsBucket",
                                bucket_name=f"{prefix}-athena-query-results-{self.region}",
                                versioned=False)
        harden_auto_delete(self, [alb_logs, athena_results])

        # Its own catalog database: the account's "default" database is shared state.
        database_name = f"{prefix.replace('-', '_')}_alb_logs"
        database = glue.CfnDatabase(self, "GlueDatabase", catalog_id=self.account,
                                    database_input=glue.CfnDatabase.DatabaseInputProperty(
                                        name=database_name))
        columns = [
            ("type", "string"), ("time", "string"), ("elb", "string"), ("client_ip", "string"),
            ("client_port", "int"), ("target_ip", "string"), ("target_port", "int"),
            ("request_processing_time", "double"), ("target_processing_time", "double"),
            ("response_processing_time", "double"), ("elb_status_code", "string"),
            ("target_status_code", "string"), ("received_bytes", "bigint"),
            ("sent_bytes", "bigint"), ("request_verb", "string"), ("request_url", "string"),
            ("request_proto", "string"), ("user_agent", "string"), ("ssl_cipher", "string"),
            ("ssl_protocol", "string"), ("target_group_arn", "string"), ("trace_id", "string"),
            ("domain_name", "string"), ("chosen_cert_arn", "string"),
            ("matched_rule_priority", "string"), ("request_creation_time", "string"),
            ("actions_executed", "string"), ("redirect_url", "string"),
            ("lambda_error_reason", "string"), ("target_port_list", "string"),
            ("target_status_code_list", "string"), ("classification", "string"),
            ("classification_reason", "string"),
        ]
        regex = (
            '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) '
            '([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) "([^ ]*) ([^ ]*) (- |[^ ]*)" '
            '"([^"]*)" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^"]*)" '
            '([-.0-9]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^ ]*)" "([^\\s]+?)" "([^\\s]+)" '
            '"([^ ]*)" "([^ ]*)"'
        )
        table = glue.CfnTable(
            self, "ALBLogTable", catalog_id=self.account, database_name=database_name,
            table_input=glue.CfnTable.TableInputProperty(
                name="alb_log", table_type="EXTERNAL_TABLE",
                parameters={"classification": "text"},
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{alb_logs.bucket_name}/AWSLogs/{self.account}/"
                             f"elasticloadbalancing/{self.region}/",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format="org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.apache.hadoop.hive.serde2.RegexSerDe",
                        parameters={"serialization.format": "1", "input.regex": regex}),
                    columns=[glue.CfnTable.ColumnProperty(name=n, type=t) for n, t in columns])))
        table.add_dependency(database)

        vpc = ec2.Vpc(
            self, "VPC", max_azs=2, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=24, name="Public",
                                        subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=24, name="Private",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ])
        alb_sg = ec2.SecurityGroup(self, "ALBSecurityGroup", vpc=vpc,
                                   description="Security group for Application Load Balancer",
                                   allow_all_outbound=True)
        # HTTPS and HTTP from inside the VPC only.
        alb_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(443),
                                "Allow HTTPS traffic from the VPC")
        alb_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(80),
                                "Allow HTTP traffic from the VPC")
        ecs_sg = ec2.SecurityGroup(self, "ECSSecurityGroup", vpc=vpc,
                                   description="Security group for ECS Fargate tasks",
                                   allow_all_outbound=True)
        ecs_sg.add_ingress_rule(alb_sg, ec2.Port.tcp(8080), "Allow traffic from ALB on port 8080")
        alb = elbv2.ApplicationLoadBalancer(
            self, "ALB", load_balancer_name=f"{prefix}-tigris-alb", vpc=vpc,
            internet_facing=False, security_group=alb_sg,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS))
        alb.log_access_logs(alb_logs)
        empty_after(alb_logs, alb)
        target_group = elbv2.ApplicationTargetGroup(
            self, "TargetGroup", target_group_name=f"{prefix}-tigris-tg", vpc=vpc, port=8080,
            protocol=elbv2.ApplicationProtocol.HTTP, target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(enabled=True, path="/health",
                                           protocol=elbv2.Protocol.HTTP,
                                           healthy_threshold_count=2,
                                           unhealthy_threshold_count=2,
                                           timeout=Duration.seconds(5),
                                           interval=Duration.seconds(30)),
            deregistration_delay=Duration.seconds(30))
        alb.add_listener("HTTPListener", port=80, protocol=elbv2.ApplicationProtocol.HTTP,
                         default_target_groups=[target_group], open=False)

        ecs_logs = logs.LogGroup(self, "ECSLogGroup", log_group_name=f"/ecs/{prefix}-danube-tigris",
                                 retention=logs.RetentionDays.ONE_WEEK,
                                 removal_policy=RemovalPolicy.DESTROY)
        function_name = f"{prefix}-tigris-entrypoint"
        lambda_logs = logs.LogGroup(self, "LambdaLogGroup",
                                    log_group_name=f"/aws/lambda/{function_name}",
                                    retention=logs.RetentionDays.ONE_WEEK,
                                    removal_policy=RemovalPolicy.DESTROY)
        cluster = ecs.Cluster(self, "ECSCluster", cluster_name=f"{prefix}-tigris", vpc=vpc,
                              container_insights=True, enable_fargate_capacity_providers=True)
        execution_role = iam.Role(
            self, "TaskExecutionRole", role_name=f"{prefix}-tigris-exec",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AmazonECSTaskExecutionRolePolicy")])
        execution_role.add_to_policy(iam.PolicyStatement(
            actions=["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
                     "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"],
            resources=["*"]))
        api_role = iam.Role(self, "TaskRole", role_name=f"{prefix}-tigris-api",
                            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"))
        api_def = ecs.FargateTaskDefinition(self, "TaskDefinition", family=f"{prefix}-tigris-api",
                                            cpu=256, memory_limit_mib=512, task_role=api_role,
                                            execution_role=execution_role)
        api_container = api_def.add_container(
            "Container", container_name="tigris-api-container",
            image=ecs.ContainerImage.from_asset(str(_ASSETS / "tigris-api")),
            cpu=256, memory_limit_mib=512, essential=True,
            logging=ecs.LogDrivers.aws_logs(stream_prefix="tigris-api", log_group=ecs_logs,
                                            mode=ecs.AwsLogDriverMode.NON_BLOCKING),
            environment={"SERVICE_NAME": "TigrisBeatsService"})
        api_container.add_port_mappings(ecs.PortMapping(container_port=8080, host_port=8080,
                                                        protocol=ecs.Protocol.TCP))
        api_service = ecs.FargateService(
            self, "FargateService", service_name=f"{prefix}-tigris-api", cluster=cluster,
            task_definition=api_def, desired_count=1, assign_public_ip=False,
            security_groups=[ecs_sg],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            health_check_grace_period=Duration.seconds(60),
            platform_version=ecs.FargatePlatformVersion.LATEST)
        api_service.attach_to_application_target_group(target_group)

        endpoint_path = ssm.StringParameter(
            self, "EndpointPathParam", parameter_name=f"/{prefix}/tigris/prod/service-config",
            string_value="/jobInstance/updateStatus")
        client_role = iam.Role(self, "ClientTaskRole", role_name=f"{prefix}-tigris-client",
                               assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"))
        client_role.add_to_policy(iam.PolicyStatement(actions=["ssm:GetParameter"],
                                                      resources=[endpoint_path.parameter_arn]))
        client_def = ecs.FargateTaskDefinition(
            self, "ClientTaskDefinition", family=f"{prefix}-tigris-client", cpu=256,
            memory_limit_mib=512, task_role=client_role, execution_role=execution_role)
        client_logs = logs.LogGroup(self, "ClientLogGroup",
                                    log_group_name=f"{prefix}-tigris-client-logs",
                                    retention=logs.RetentionDays.ONE_WEEK,
                                    removal_policy=RemovalPolicy.DESTROY)
        client_def.add_container(
            "TigrisClient", container_name="tigris-client",
            image=ecs.ContainerImage.from_asset(str(_ASSETS / "tigris-client")),
            cpu=256, memory_limit_mib=512, essential=True,
            logging=ecs.LogDrivers.aws_logs(stream_prefix="tigris-client", log_group=client_logs),
            environment={"AWS_REGION": self.region, "ALB_DNS_NAME": alb.load_balancer_dns_name,
                         "ENDPOINT_PATH_PARAM": endpoint_path.parameter_name})
        client_service = ecs.FargateService(
            self, "ClientService", service_name=f"{prefix}-tigris-client", cluster=cluster,
            task_definition=client_def, desired_count=1, assign_public_ip=False,
            security_groups=[ecs_sg],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            platform_version=ecs.FargatePlatformVersion.LATEST)

        lambda_role = iam.Role(
            self, "LambdaRole", role_name=f"{prefix}-danube-lambda",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")])
        entrypoint = lambda_.Function(
            self, "LambdaFunction", function_name=function_name,
            runtime=lambda_.Runtime.NODEJS_18_X, handler="index.handler",
            code=lambda_.Code.from_inline("exports.handler = async () => ({ statusCode: 200 });"),
            memory_size=128, timeout=Duration.seconds(30), role=lambda_role, log_group=lambda_logs,
            environment={"SERVICE_NAME": "TigrisBeatsService"})

        export(self, "ALBLogsBucketName", alb_logs.bucket_name)
        export(self, "AthenaResultsBucketName", athena_results.bucket_name)
        export(self, "ALBDnsName", alb.load_balancer_dns_name)
        export(self, "ALBArn", alb.load_balancer_arn)
        export(self, "TargetGroupArn", target_group.target_group_arn)
        export(self, "ECSClusterName", cluster.cluster_name)
        export(self, "ECSServiceName", api_service.service_name)
        export(self, "ECSLogGroupName", ecs_logs.log_group_name)
        export(self, "LambdaFunctionName", entrypoint.function_name)
        export(self, "LambdaLogGroupName", lambda_logs.log_group_name)
        export(self, "GlueTableName", table.ref)
        export(self, "GlueDatabaseName", database.ref)
        export(self, "EndpointPathParamName", endpoint_path.parameter_name)
        export(self, "ClientServiceName", client_service.service_name)
        export(self, "ClientLogGroupName", client_logs.log_group_name)


class AgreementsApiStack(cdk.Stack):
    """An IAM-authorized REST API over a lookup function; it has no deployment or stage."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        agreements = dynamodb.Table(
            self, "AgreementsTable",
            partition_key=dynamodb.Attribute(name="agreementId",
                                             type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY)
        role = iam.Role(self, "LambdaExecutionRole",
                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                            "service-role/AWSLambdaBasicExecutionRole")])
        agreements.grant_read_data(role)
        get_agreement = lambda_.Function(
            self, "GetAgreementFunction", runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler", code=asset("get_agreement"), role=role,
            environment={"TABLE_NAME": agreements.table_name}, timeout=Duration.seconds(30))
        # deploy=False: no deployment and no stage, so nothing outside the account reaches it;
        # TestInvokeMethod exercises it.
        api = apigateway.RestApi(
            self, "ServiceApi", rest_api_name=f"{prefix}-quartz-d3a",
            description="Data Access Aggregator & Auditor Service API",
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]),
            deploy=False)
        agreement = api.root.add_resource("data-agreements").add_resource("{agreementId}")
        agreement.add_method("GET", apigateway.LambdaIntegration(get_agreement, proxy=True),
                             authorization_type=apigateway.AuthorizationType.IAM)
        arn = f"arn:{self.partition}:execute-api:{self.region}:{self.account}"
        # The export pipeline's grant names the API it was built against, not this one.
        data_export = iam.Role(self, "DataExportRole",
                               assumed_by=iam.AccountPrincipal(self.account),
                               description="Role for data export API integration")
        data_export.add_to_policy(iam.PolicyStatement(
            actions=["execute-api:Invoke"], resources=[f"{arn}:a1b2c3d4e5/beta/GET/*"]))
        restricted = iam.Role(self, "RestrictedAccessRole",
                              assumed_by=iam.AccountPrincipal(self.account),
                              description="Role for accessing service endpoints")
        restricted.add_to_policy(iam.PolicyStatement(
            actions=["execute-api:Invoke"], resources=[f"{arn}:{api.rest_api_id}/beta/POST/*"]))

        export(self, "ApiId", api.rest_api_id)
        export(self, "StageName", "beta")
        export(self, "TableName", agreements.table_name)
        export(self, "TableArn", agreements.table_arn)
        export(self, "LambdaFunctionName", get_agreement.function_name)
        export(self, "LambdaFunctionArn", get_agreement.function_arn)
        export(self, "RestrictedRoleArn", restricted.role_arn)
        export(self, "AgreementId", "dua-2024-001")
        export(self, "AgreementPath", "/data-agreements/dua-2024-001")


class StreamManagerStack(cdk.Stack):
    """A WebSocket API (L1) with routes and a deployment but no stage, and a scripts bucket."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        def table(construct_id_: str, name: str, key: str) -> dynamodb.Table:
            return dynamodb.Table(self, construct_id_, table_name=f"{prefix}-{name}",
                                  partition_key=dynamodb.Attribute(
                                      name=key, type=dynamodb.AttributeType.STRING),
                                  billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
                                  removal_policy=RemovalPolicy.DESTROY)

        connections = table("ConnectionsTable", "stream-websocket-connections", "connectionId")
        nodes = table("NodesTable", "stream-nodes", "nodeId")
        deployments = table("DeploymentsTable", "stream-deployments", "deploymentId")
        role = iam.Role(self, "LambdaExecutionRole",
                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                            "service-role/AWSLambdaBasicExecutionRole")])
        role.add_to_policy(iam.PolicyStatement(
            actions=["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem",
                     "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
            resources=[connections.table_arn, nodes.table_arn, deployments.table_arn]))
        name = f"{prefix}-stream-message"
        log_group = logs.LogGroup(self, "LambdaLogGroup", log_group_name=f"/aws/lambda/{name}",
                                  retention=logs.RetentionDays.ONE_WEEK,
                                  removal_policy=RemovalPolicy.DESTROY)
        handler = lambda_.Function(
            self, "MessageHandler", function_name=name, runtime=lambda_.Runtime.NODEJS_18_X,
            handler="message.handler", code=asset("message-handler"),
            timeout=Duration.seconds(30), memory_size=128, role=role, log_group=log_group,
            environment={"CONNECTIONS_TABLE_NAME": connections.table_name,
                         "WEBSOCKET_CONNECTIONS_TABLE": connections.table_name,
                         "DEPLOYMENTS_TABLE": deployments.table_name,
                         "NODES_TABLE": nodes.table_name,
                         "DEPLOYMENTS_TABLE_NAME": deployments.table_name,
                         "NODES_TABLE_NAME": nodes.table_name})
        api = apigwv2.CfnApi(self, "WebSocketApi", name=f"{prefix}-stream-manager-websocket",
                             protocol_type="WEBSOCKET",
                             route_selection_expression="$request.body.action")
        integration = apigwv2.CfnIntegration(
            self, "LambdaIntegration", api_id=api.ref, integration_type="AWS_PROXY",
            integration_uri=f"arn:{self.partition}:apigateway:{self.region}:lambda:path/"
                            f"2015-03-31/functions/{handler.function_arn}/invocations")
        routes = [
            apigwv2.CfnRoute(self, f"{label}Route", api_id=api.ref, route_key=key,
                             target=f"integrations/{integration.ref}")
            for label, key in (("Connect", "$connect"), ("Default", "$default"),
                               ("Disconnect", "$disconnect"))
        ]
        # A deployment without a stage: nothing serves it, so nothing outside the account
        # reaches the handler through it.
        deployment = apigwv2.CfnDeployment(self, "Deployment", api_id=api.ref)
        for route in routes:
            deployment.add_dependency(route)
        api_arn = f"arn:{self.partition}:execute-api:{self.region}:{self.account}:{api.ref}"
        handler.add_permission("ApiGatewayInvoke",
                               principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
                               source_arn=f"{api_arn}/*")
        role.add_to_policy(iam.PolicyStatement(actions=["execute-api:ManageConnections"],
                                               resources=[f"{api_arn}/*"]))

        scripts = bucket(self, "NodeScriptsBucket", bucket_name=f"{prefix}-flint-node-scripts",
                         versioned=True)
        upload = s3deploy.BucketDeployment(
            self, "DeployNodeScripts",
            sources=[s3deploy.Source.asset(str(_ASSETS / "node-scripts"))],
            destination_bucket=scripts)
        empty_after(scripts, upload)
        harden_auto_delete(self, [scripts])

        export(self, "WebSocketApiId", api.ref)
        export(self, "DeploymentId", deployment.ref)
        export(self, "LambdaFunctionName", handler.function_name)
        export(self, "LambdaFunctionArn", handler.function_arn)
        export(self, "LogGroupName", log_group.log_group_name)
        export(self, "NodeScriptsBucketName", scripts.bucket_name)
        export(self, "ConnectionsTableName", connections.table_name)
        export(self, "NodesTableName", nodes.table_name)
        export(self, "DeploymentsTableName", deployments.table_name)


class OnyxStack(cdk.Stack):
    """DynamoDB stream processors per stage, a buffer-timeout function, queues, topics, an alarm."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        def table(construct_id_: str, name: str) -> dynamodb.Table:
            return dynamodb.Table(self, construct_id_, table_name=f"{prefix}-{name}",
                                  partition_key=dynamodb.Attribute(
                                      name="id", type=dynamodb.AttributeType.STRING),
                                  stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
                                  removal_policy=RemovalPolicy.DESTROY,
                                  billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST)

        regression = table("RegressionRequestsTable", "BasaltRegressionRequests-alpha")
        bulk_regression = table("BulkRegressionRequestsTable",
                                "BulkBasaltRegressionRequests-alpha")
        requests = table("BasaltRequestsTable", "BasaltRequests-alpha")
        bulk_requests = table("BulkBasaltRequestsTable", "BulkBasaltRequests-alpha")
        regression_beta = table("RegressionRequestsBetaTable", "BasaltRegressionRequests-beta")
        requests_beta = table("BasaltRequestsBetaTable", "BasaltRequests-beta")
        regression_gamma = table("RegressionRequestsGammaTable",
                                 "BasaltRegressionRequests-gamma")
        requests_gamma = table("BasaltRequestsGammaTable", "BasaltRequests-gamma")
        alpha_tables = (regression, bulk_regression, requests, bulk_requests)

        retry_queue = sqs.Queue(self, "RetryQueue", queue_name=f"{prefix}-OnyxRetryQueue-alpha",
                                visibility_timeout=Duration.seconds(1800),
                                removal_policy=RemovalPolicy.DESTROY)
        dlq = sqs.Queue(self, "DLQ", queue_name=f"{prefix}-OnyxDLQ-alpha",
                        retention_period=Duration.days(14), removal_policy=RemovalPolicy.DESTROY)
        error_topic = sns.Topic(self, "ErrorTopic", topic_name=f"{prefix}-OnyxErrors-alpha",
                                display_name="Onyx Lambda Error Notifications")
        skipped_topic = sns.Topic(self, "SkippedRecordsTopic",
                                  topic_name=f"{prefix}-OnyxSkippedRecords-alpha",
                                  display_name="Onyx Lambda Skipped Records Notifications")
        basic = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaBasicExecutionRole")

        onyx_role = iam.Role(self, "OnyxRole",
                             assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                             description="Execution role for Onyx Lambda handler",
                             managed_policies=[basic])
        for t in alpha_tables:
            t.grant_stream_read(onyx_role)
            t.grant_read_data(onyx_role)
        retry_queue.grant_send_messages(onyx_role)
        retry_queue.grant_consume_messages(onyx_role)
        dlq.grant_send_messages(onyx_role)
        error_topic.grant_publish(onyx_role)
        skipped_topic.grant_publish(onyx_role)
        onyx_role.add_to_policy(iam.PolicyStatement(actions=["cloudwatch:PutMetricData"],
                                                    resources=["*"]))
        onyx = lambda_.Function(
            self, "OnyxFunction", function_name=f"{prefix}-OnyxHandler-alpha",
            runtime=lambda_.Runtime.PYTHON_3_10, handler="index.handler",
            code=asset("onyx_handler"), timeout=Duration.seconds(300), memory_size=512,
            role=onyx_role,
            environment={"LOGLEVEL": "10", "STAGE": "alpha",
                         "BASALT_REQUESTS_TABLE": requests.table_name,
                         "BULK_BASALT_REQUESTS_TABLE": bulk_requests.table_name,
                         "ONYX_ERROR_SNS_TOPIC_ARN": error_topic.topic_arn,
                         "ONYX_RETRY_QUEUE_URL": retry_queue.queue_url,
                         "ONYX_DLQ_URL": dlq.queue_url,
                         "ONYX_SKIPPED_RECORDS_TOPIC_ARN": skipped_topic.topic_arn},
            description="Processes DynamoDB streams to start Quartz runs - alpha stage",
            log_retention=logs.RetentionDays.TEN_YEARS, dead_letter_queue=dlq)
        for t in alpha_tables:
            onyx.add_event_source(event_sources.DynamoEventSource(
                t, starting_position=lambda_.StartingPosition.LATEST, batch_size=1,
                retry_attempts=3))
        onyx.add_event_source(event_sources.SqsEventSource(retry_queue, batch_size=1))

        skipped_alarm = cloudwatch.Alarm(
            self, "SkippedRecordsAlarm", alarm_name=f"{prefix}-OnyxSkippedRecords-alpha",
            alarm_description="Alert when Onyx Lambda skips records - may indicate filter "
                              "logic issue",
            metric=cloudwatch.Metric(namespace="Basalt/Onyx", metric_name="SkippedRecords",
                                     statistic="Sum", period=Duration.minutes(5)),
            threshold=5, evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD)
        skipped_alarm.add_alarm_action(cloudwatch_actions.SnsAction(skipped_topic))

        beta_role = iam.Role(self, "OnyxBetaRole",
                             assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                             description="Execution role for Onyx Lambda handler - beta",
                             managed_policies=[basic])
        for t in (regression_beta, requests_beta):
            t.grant_stream_read(beta_role)
            t.grant_read_data(beta_role)
        beta = lambda_.Function(
            self, "OnyxBetaFunction", function_name=f"{prefix}-OnyxHandler-beta",
            runtime=lambda_.Runtime.PYTHON_3_10, handler="index.handler",
            code=asset("onyx_handler_beta"), timeout=Duration.seconds(300), memory_size=512,
            role=beta_role, environment={"LOGLEVEL": "20", "STAGE": "beta"},
            description="Lambda function for Onyx integration - beta stage",
            log_retention=logs.RetentionDays.ONE_YEAR)
        for t in (regression_beta, requests_beta):
            beta.add_event_source(event_sources.DynamoEventSource(
                t, starting_position=lambda_.StartingPosition.LATEST, batch_size=1,
                retry_attempts=3))

        buffer_role = iam.Role(self, "BufferTimeoutRole",
                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                               description="Execution role for Buffer Timeout handler",
                               managed_policies=[basic])
        for t in alpha_tables:
            t.grant_read_write_data(buffer_role)
        buffer_timeout = lambda_.Function(
            self, "BufferTimeoutFunction", function_name=f"{prefix}-BufferTimeout-alpha",
            runtime=lambda_.Runtime.PYTHON_3_10, handler="index.handler",
            code=asset("buffer_timeout_handler"), timeout=Duration.seconds(90),
            memory_size=256, role=buffer_role,
            environment={"LOGLEVEL": "10", "STAGE": "alpha",
                         "REGRESSION_REQUESTS_TABLE": regression.table_name,
                         "BASALT_REQUESTS_TABLE": requests.table_name},
            description="Lambda function for handling buffer timeout transitions - alpha stage",
            log_retention=logs.RetentionDays.ONE_YEAR)

        for label, t in (("RegressionRequests", regression),
                         ("BulkRegressionRequests", bulk_regression),
                         ("BasaltRequests", requests), ("BulkBasaltRequests", bulk_requests)):
            export(self, f"{label}TableName", t.table_name)
            export(self, f"{label}StreamArn", t.table_stream_arn)
        export(self, "RegressionRequestsBetaTableName", regression_beta.table_name)
        export(self, "BasaltRequestsBetaTableName", requests_beta.table_name)
        export(self, "RegressionRequestsGammaTableName", regression_gamma.table_name)
        export(self, "BasaltRequestsGammaTableName", requests_gamma.table_name)
        export(self, "OnyxFunctionName", onyx.function_name)
        export(self, "OnyxFunctionArn", onyx.function_arn)
        export(self, "OnyxLogGroup", onyx.log_group.log_group_name)
        export(self, "RetryQueueUrl", retry_queue.queue_url)
        export(self, "DLQUrl", dlq.queue_url)
        export(self, "ErrorTopicArn", error_topic.topic_arn)
        export(self, "SkippedRecordsTopicArn", skipped_topic.topic_arn)
        export(self, "SkippedRecordsAlarmName", skipped_alarm.alarm_name)
        export(self, "OnyxBetaFunctionName", beta.function_name)
        export(self, "BufferTimeoutFunctionName", buffer_timeout.function_name)


class StaleTargetsSearchStack(cdk.Stack):
    """A VPC domain behind an internal ALB whose target groups hold addresses nothing answers on."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        vpc = ec2.Vpc(
            self, "Vpc", vpc_name=f"{prefix}-flint-analytics-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.80.0.0/16"), max_azs=2, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=22, name="Public",
                                        subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=22, name="Private",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ])
        flow_log_group = logs.LogGroup(
            self, "FlowLogGroup", log_group_name=f"/aws/vpc/{prefix}-flint-analytics-flowlogs",
            retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)
        ec2.FlowLog(self, "VpcFlowLog", resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
                    destination=ec2.FlowLogDestination.to_cloud_watch_logs(flow_log_group))
        search_sg = ec2.SecurityGroup(self, "OpenSearchSg", vpc=vpc,
                                      description="OpenSearch domain SG", allow_all_outbound=True)
        alb_sg = ec2.SecurityGroup(self, "AlbSg", vpc=vpc, description="Internal ALB SG",
                                   allow_all_outbound=True)
        search_sg.add_ingress_rule(alb_sg, ec2.Port.tcp(443), "HTTPS from ALB")
        alb_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(443),
                                "HTTPS from VPC")
        key = kms.Key(self, "OsKey", description="Encryption key for flint-analytics OpenSearch",
                      enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)
        # The admin user's password is generated into a Secrets Manager secret.
        domain = opensearch.Domain(
            self, "AnalyticsDomain", domain_name=f"{prefix}-analytics",
            version=opensearch.EngineVersion.OPENSEARCH_2_11,
            capacity=opensearch.CapacityConfig(data_nodes=1,
                                               data_node_instance_type="t3.small.search",
                                               multi_az_with_standby_enabled=False),
            ebs=opensearch.EbsOptions(enabled=True, volume_size=10,
                                      volume_type=ec2.EbsDeviceVolumeType.GP3),
            vpc=vpc, vpc_subnets=[ec2.SubnetSelection(subnets=vpc.private_subnets[:1])],
            security_groups=[search_sg],
            encryption_at_rest=opensearch.EncryptionAtRestOptions(enabled=True, kms_key=key),
            node_to_node_encryption=True, enforce_https=True,
            tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2,
            fine_grained_access_control=opensearch.AdvancedSecurityOptions(
                master_user_name="admin"),
            removal_policy=RemovalPolicy.DESTROY)
        domain.add_access_policies(iam.PolicyStatement(
            principals=[iam.AnyPrincipal()], actions=["es:*"],
            resources=[f"{domain.domain_arn}/*"],
            conditions={"StringEquals": {"aws:PrincipalAccount": cdk.Aws.ACCOUNT_ID}}))
        alb = elbv2.ApplicationLoadBalancer(
            self, "AnalyticsAlb", load_balancer_name=f"{prefix}-flint-alb", vpc=vpc,
            internet_facing=False, security_group=alb_sg,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS))

        def https_group(construct_id_: str, name: str, path: str):
            group = elbv2.ApplicationTargetGroup(
                self, construct_id_, target_group_name=f"{prefix}-{name}", vpc=vpc, port=443,
                protocol=elbv2.ApplicationProtocol.HTTPS, target_type=elbv2.TargetType.IP,
                health_check=elbv2.HealthCheck(enabled=True, protocol=elbv2.Protocol.HTTPS,
                                               port="443", path=path,
                                               interval=Duration.seconds(30),
                                               timeout=Duration.seconds(10),
                                               healthy_threshold_count=2,
                                               unhealthy_threshold_count=3,
                                               healthy_http_codes="200,301,302"))
            # Addresses the domain held before its last blue/green deployment.
            group.add_target(elbv2_targets.IpTarget("10.80.4.37", 443))
            group.add_target(elbv2_targets.IpTarget("10.80.8.112", 443))
            return group

        dashboards = https_group("DashboardsTg", "dashboards-tg", "/_cluster/health")
        api_group = https_group("ApiTg", "flint-api-tg", "/")
        listener = alb.add_listener("HttpListener", port=80,
                                    protocol=elbv2.ApplicationProtocol.HTTP, open=False,
                                    default_action=elbv2.ListenerAction.forward([dashboards]))
        listener.add_action("ApiRoute", priority=10, conditions=[
            elbv2.ListenerCondition.path_patterns(["/_cat/*", "/_cluster/*", "/_nodes/*"])],
            action=elbv2.ListenerAction.forward([api_group]))
        alarm = cloudwatch.Alarm(
            self, "UnhealthyHostsAlarm", alarm_name=f"{prefix}-flint-analytics-unhealthy-hosts",
            metric=cloudwatch.Metric(
                namespace="AWS/ApplicationELB", metric_name="UnHealthyHostCount",
                dimensions_map={"TargetGroup": dashboards.target_group_full_name,
                                "LoadBalancer": alb.load_balancer_full_name},
                statistic="Maximum", period=Duration.minutes(1)),
            threshold=0, comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            evaluation_periods=2, treat_missing_data=cloudwatch.TreatMissingData.BREACHING)

        export(self, "VpcId", vpc.vpc_id)
        export(self, "DomainName", domain.domain_name)
        export(self, "DomainEndpoint", domain.domain_endpoint)
        export(self, "DomainArn", domain.domain_arn)
        export(self, "AlbDnsName", alb.load_balancer_dns_name)
        export(self, "AlbArn", alb.load_balancer_arn)
        export(self, "DashboardsTgArn", dashboards.target_group_arn)
        export(self, "ApiTgArn", api_group.target_group_arn)
        export(self, "AlarmName", alarm.alarm_name)
        export(self, "FlowLogGroupName", flow_log_group.log_group_name)


class DeploymentStatusStack(cdk.Stack):
    """A deployment-status parameter and the names of two service stacks it tracks."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        param = ssm.StringParameter(self, "TigrisDeploymentConfig",
                                    parameter_name=f"/{prefix}/tigris/deployment-status",
                                    string_value="pending")
        export(self, "DeploymentStatusParamName", param.parameter_name)
        export(self, "FailedStackName", f"{prefix}-TigrisService")
        export(self, "FailedWorkerStackName", f"{prefix}-TigrisWorker")


class TenantProvisioningStack(cdk.Stack):
    """A tenant table, a tenant content bucket behind a disabled distribution, and a workflow."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        tenants = dynamodb.Table(
            self, "TenantsTable",
            partition_key=dynamodb.Attribute(name="tenant_id", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY)
        tenants.add_global_secondary_index(
            index_name="OwnerIndex",
            partition_key=dynamodb.Attribute(name="owner_user_id",
                                             type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL)
        content = bucket(self, "TenantServicesBucket", bucket_name=f"{prefix}-tenant-content",
                         versioned=True)
        content.add_to_resource_policy(iam.PolicyStatement(
            sid="AllowCloudFrontServicePrincipal",
            principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
            actions=["s3:GetObject"], resources=[f"{content.bucket_arn}/*"],
            conditions={"StringLike": {
                "AWS:SourceArn": f"arn:{self.partition}:cloudfront::{self.account}:"
                                 f"distribution/*"}}))
        harden_auto_delete(self, [content])
        oac = cloudfront.CfnOriginAccessControl(
            self, "TenantOAC",
            origin_access_control_config=cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name=f"{prefix}-saas-tenant-oac", origin_access_control_origin_type="s3",
                signing_behavior="always", signing_protocol="sigv4"))
        # Disabled: it would serve the bucket's tenant content to anyone, and the estate is
        # never reachable from outside the account.
        distribution = cloudfront.CfnDistribution(
            self, "MultiTenantDistribution",
            distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
                enabled=False, comment="Multi-tenant distribution",
                origins=[cloudfront.CfnDistribution.OriginProperty(
                    id="S3Origin", domain_name=content.bucket_regional_domain_name,
                    origin_access_control_id=oac.attr_id,
                    s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty())],
                default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                    target_origin_id="S3Origin", viewer_protocol_policy="redirect-to-https",
                    cache_policy_id=_CACHING_OPTIMIZED, compress=True,
                    allowed_methods=["GET", "HEAD", "OPTIONS"], cached_methods=["GET", "HEAD"]),
                http_version="http2", ipv6_enabled=False))

        def step_function(construct_id_: str, code: str, timeout_s: int, env: dict):
            return lambda_.Function(self, construct_id_, runtime=lambda_.Runtime.PYTHON_3_12,
                                    handler="index.handler", code=asset(code),
                                    timeout=Duration.seconds(timeout_s), environment=env)

        provision = step_function("ProvisionKeyspaceFunction", "provision_keyspace", 60,
                                  {"TENANTS_TABLE_NAME": tenants.table_name,
                                   "TENANT_SERVICES_BUCKET": content.bucket_name})
        tenants.grant_read_write_data(provision)
        content.grant_read_write(provision)
        configure = step_function("ConfigureTenantUrlFunction", "configure_tenant_url", 30,
                                  {"TENANTS_TABLE_NAME": tenants.table_name,
                                   "DISTRIBUTION_DOMAIN": distribution.attr_domain_name})
        tenants.grant_read_write_data(configure)
        check_content = step_function("CheckTenantContentFunction", "check_tenant_content", 30,
                                      {"TENANT_SERVICES_BUCKET": content.bucket_name})
        content.grant_read(check_content)
        complete = step_function("CompleteProvisioningFunction", "complete_provisioning", 30,
                                 {"TENANTS_TABLE_NAME": tenants.table_name})
        tenants.grant_read_write_data(complete)
        # The provisioner writes into the bucket, so it is gone before the bucket is emptied.
        empty_after(content, provision)

        chain = tasks.LambdaInvoke(self, "ProvisionTenantKeyspace", lambda_function=provision,
                                   output_path="$.Payload")
        chain = chain.next(tasks.LambdaInvoke(self, "ConfigureTenantUrl",
                                              lambda_function=configure, output_path="$.Payload"))
        chain = chain.next(tasks.LambdaInvoke(self, "CheckTenantContent",
                                              lambda_function=check_content,
                                              output_path="$.Payload"))
        chain = chain.next(tasks.LambdaInvoke(self, "CompleteProvisioning",
                                              lambda_function=complete, output_path="$.Payload"))
        workflow = sfn.StateMachine(self, "TenantProvisioningWorkflow",
                                    definition_body=sfn.DefinitionBody.from_chainable(chain),
                                    timeout=Duration.minutes(15), tracing_enabled=True)

        export(self, "TenantsTableName", tenants.table_name)
        export(self, "TenantServicesBucketName", content.bucket_name)
        export(self, "DistributionId", distribution.attr_id)
        export(self, "DistributionDomainName", distribution.attr_domain_name)
        export(self, "TenantProvisioningWorkflowArn", workflow.state_machine_arn)


class AnalyticsBucketsStack(cdk.Stack):
    """Three KMS-encrypted, versioned analytics buckets the western functions write into."""

    def __init__(self, scope, construct_id, *, names: dict[str, str], **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        key = kms.Key(self, "AnalyticsKey", description="KMS key for analytics bucket encryption",
                      enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)

        def kms_bucket(construct_id_: str, name: str, **kw) -> s3.Bucket:
            return bucket(self, construct_id_, bucket_name=name, versioned=True,
                          encryption=s3.BucketEncryption.KMS, encryption_key=key, **kw)

        analytics = kms_bucket("AnalyticsBucket", names["analytics"])
        archive = kms_bucket("ArchiveBucket", names["archive"], lifecycle_rules=[
            s3.LifecycleRule(transitions=[s3.Transition(storage_class=s3.StorageClass.GLACIER,
                                                        transition_after=Duration.days(90))])])
        reports = kms_bucket("ReportsBucket", names["reports"])
        harden_auto_delete(self, [analytics, archive, reports])

        export(self, "AnalyticsBucketName", analytics.bucket_name)
        export(self, "AnalyticsBucketArn", analytics.bucket_arn)
        export(self, "ArchiveBucketName", archive.bucket_name)
        export(self, "ReportsBucketName", reports.bucket_name)
        export(self, "KmsKeyId", key.key_id)
        export(self, "KmsKeyArn", key.key_arn)


class ReconciliationStack(cdk.Stack):
    """SQS-driven reconciliation in isolated subnets, writing to analytics buckets elsewhere.

    The isolated subnets reach S3 only through this region's gateway endpoint.
    """

    def __init__(self, scope, construct_id, *, prefix: str, analytics_region: str,
                 names: dict[str, str], **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        main_vpc = ec2.Vpc(
            self, "MainVPC", vpc_name=f"{prefix}-quartz-beta-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"), max_azs=2,
            enable_dns_hostnames=True, enable_dns_support=True, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="PublicSubnet", subnet_type=ec2.SubnetType.PUBLIC,
                                        cidr_mask=24),
                ec2.SubnetConfiguration(name="PrivateSubnet",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                                        cidr_mask=24),
                ec2.SubnetConfiguration(name="IsolatedSubnet",
                                        subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                                        cidr_mask=24),
            ])
        main_vpc.add_gateway_endpoint("S3GatewayEndpoint",
                                      service=ec2.GatewayVpcEndpointAwsService.S3)
        main_vpc.add_gateway_endpoint("DynamoDBGatewayEndpoint",
                                      service=ec2.GatewayVpcEndpointAwsService.DYNAMODB)
        main_vpc.add_interface_endpoint("SQSInterfaceEndpoint",
                                        service=ec2.InterfaceVpcEndpointAwsService.SQS,
                                        private_dns_enabled=True)

        def sg(vpc, construct_id_: str, description: str) -> ec2.SecurityGroup:
            return ec2.SecurityGroup(self, construct_id_, vpc=vpc, description=description,
                                     allow_all_outbound=True)

        reconciliation_sg = sg(main_vpc, "ReconciliationProcessorSG",
                               "Security group for reconciliation processor Lambda")
        processor_sg = sg(main_vpc, "AnalyticsProcessorSG",
                          "Security group for analytics processor Lambda")
        writer_sg = sg(main_vpc, "AnalyticsWriterSG", "Security group for analytics writer Lambda")
        dev_vpc = ec2.Vpc(
            self, "DevVPC", vpc_name=f"{prefix}-quartz-dev-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.1.0.0/16"), max_azs=2,
            enable_dns_hostnames=True, enable_dns_support=True, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="PublicSubnet", subnet_type=ec2.SubnetType.PUBLIC,
                                        cidr_mask=24),
                ec2.SubnetConfiguration(name="PrivateSubnet",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                                        cidr_mask=24),
            ])
        dev_vpc.add_gateway_endpoint("DevS3GatewayEndpoint",
                                     service=ec2.GatewayVpcEndpointAwsService.S3)
        dev_sg = sg(dev_vpc, "DevProcessorSG", "Security group for dev processor Lambda")

        west_key = kms.Key(self, "WestKey", description="KMS key for regional bucket encryption",
                           enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)

        def kms_bucket(construct_id_: str, name: str, **kw) -> s3.Bucket:
            return bucket(self, construct_id_, bucket_name=f"{prefix}-{name}-{self.region}",
                          encryption=s3.BucketEncryption.KMS, encryption_key=west_key, **kw)

        config_bucket = kms_bucket("ConfigBucket", "quartz-config-beta", versioned=True)
        temp_bucket = kms_bucket("TempBucket", "quartz-temp-beta",
                                 lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(7))])
        backup_bucket = kms_bucket("BackupBucket", "quartz-backup-beta", versioned=True)
        harden_auto_delete(self, [config_bucket, temp_bucket, backup_bucket])

        sqs_key = kms.Key(self, "SQSKey", description="KMS key for SQS queue encryption",
                          enable_key_rotation=True, removal_policy=RemovalPolicy.DESTROY)
        dlq = sqs.Queue(self, "DLQ", queue_name=f"{prefix}-reconciliation-request-dlq-beta",
                        retention_period=Duration.days(14), removal_policy=RemovalPolicy.DESTROY)
        input_queue = sqs.Queue(
            self, "InputQueue", queue_name=f"{prefix}-reconciliation-request-beta",
            visibility_timeout=Duration.seconds(600), retention_period=Duration.days(14),
            dead_letter_queue=sqs.DeadLetterQueue(queue=dlq, max_receive_count=3),
            removal_policy=RemovalPolicy.DESTROY)
        output_queue = sqs.Queue(
            self, "OutputQueue", queue_name=f"{prefix}-reconciliation-response-beta",
            visibility_timeout=Duration.seconds(300), retention_period=Duration.days(14),
            removal_policy=RemovalPolicy.DESTROY)

        # Each queue is encrypted with the stack's own key.
        for queue in (dlq, input_queue, output_queue):
            queue.node.default_child.kms_master_key_id = sqs_key.key_arn
        s3_arn = f"arn:{self.partition}:s3:::"
        analytics_arn = f"{s3_arn}{names['analytics']}"
        archive_arn = f"{s3_arn}{names['archive']}"
        reports_arn = f"{s3_arn}{names['reports']}"
        vpc_access = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaVPCAccessExecutionRole")

        def role(construct_id_: str, name: str, managed=vpc_access) -> iam.Role:
            return iam.Role(self, construct_id_, role_name=f"{prefix}-{name}",
                            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                            managed_policies=[managed])

        def function_logs(construct_id_: str, name: str) -> logs.LogGroup:
            return logs.LogGroup(self, construct_id_, log_group_name=f"/aws/lambda/{name}",
                                 retention=logs.RetentionDays.ONE_WEEK,
                                 removal_policy=RemovalPolicy.DESTROY)

        reconciliation_role = role("ReconciliationRole", "quartz-beta-reconciliation")
        reconciliation_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:PutObject", "s3:GetObject"],
            resources=[f"{analytics_arn}/*", f"{archive_arn}/*", f"{reports_arn}/*"]))
        reconciliation_role.add_to_policy(iam.PolicyStatement(
            actions=["sqs:*"], resources=[output_queue.queue_arn, input_queue.queue_arn]))
        reconciliation_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
            resources=["*"]))
        reconciliation_name = f"{prefix}-reconciliation-processor-beta"
        reconciliation_logs = function_logs("ReconciliationLogGroup", reconciliation_name)
        reconciliation = lambda_.Function(
            self, "ReconciliationProcessor", function_name=reconciliation_name,
            runtime=lambda_.Runtime.PYTHON_3_11, handler="index.handler",
            code=asset("reconciliation-processor"), timeout=Duration.seconds(600),
            memory_size=2048, role=reconciliation_role, vpc=main_vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=main_vpc.isolated_subnets),
            security_groups=[reconciliation_sg],
            environment={"INPUT_QUEUE_URL": input_queue.queue_url,
                         "OUTPUT_QUEUE_URL": output_queue.queue_url,
                         "ANALYTICS_S3_BUCKET": names["analytics"],
                         "ANALYTICS_S3_REGION": analytics_region, "LOG_LEVEL": "WARN"},
            log_group=reconciliation_logs)
        reconciliation.add_event_source(event_sources.SqsEventSource(
            input_queue, batch_size=1, max_batching_window=Duration.seconds(0)))
        input_queue.grant_consume_messages(reconciliation)
        output_queue.grant_send_messages(reconciliation)
        cloudwatch.Alarm(
            self, "ReconciliationTimeoutAlarm", alarm_name=f"{prefix}-reconciliation-timeout",
            metric=reconciliation.metric_duration(statistic="Maximum"),
            threshold=590000, evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING)

        processor_role = role("AnalyticsProcessorRole", "quartz-beta-analytics-processor")
        processor_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:PutObject"],
            resources=[f"{analytics_arn}/*", f"{archive_arn}/*"]))
        processor_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], resources=["*"]))
        processor_name = f"{prefix}-analytics-processor-beta"
        lambda_.Function(
            self, "AnalyticsProcessor", function_name=processor_name,
            runtime=lambda_.Runtime.PYTHON_3_11, handler="index.handler",
            code=asset("analytics-processor"), timeout=Duration.seconds(300), memory_size=1024,
            role=processor_role, vpc=main_vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=main_vpc.private_subnets),
            security_groups=[processor_sg],
            environment={"ANALYTICS_BUCKET": names["analytics"],
                         "ARCHIVE_BUCKET": names["archive"], "REGION": analytics_region},
            log_group=function_logs("AnalyticsProcessorLogGroup", processor_name))

        writer_role = role("AnalyticsWriterRole", "quartz-beta-analytics-writer")
        writer_role.add_to_policy(iam.PolicyStatement(actions=["s3:PutObject"],
                                                      resources=[f"{reports_arn}/*"]))
        writer_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], resources=["*"]))
        writer_name = f"{prefix}-analytics-writer-beta"
        # Public subnets: a function's network interfaces never take a public address, so this
        # function has no route out at all.
        lambda_.Function(
            self, "AnalyticsWriter", function_name=writer_name,
            runtime=lambda_.Runtime.PYTHON_3_11, handler="index.handler",
            code=asset("analytics-writer"), timeout=Duration.seconds(180), memory_size=512,
            role=writer_role, vpc=main_vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=main_vpc.public_subnets),
            allow_public_subnet=True, security_groups=[writer_sg],
            environment={"REPORTS_BUCKET": names["reports"], "REGION": analytics_region},
            log_group=function_logs("AnalyticsWriterLogGroup", writer_name))

        dev_role = role("DevProcessorRole", "quartz-dev-processor")
        dev_role.add_to_policy(iam.PolicyStatement(actions=["s3:GetObject", "s3:PutObject"],
                                                   resources=[f"{analytics_arn}/*"]))
        dev_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], resources=["*"]))
        dev_name = f"{prefix}-dev-processor-beta"
        lambda_.Function(
            self, "DevProcessor", function_name=dev_name, runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler", code=asset("dev-processor"), timeout=Duration.seconds(300),
            memory_size=1024, role=dev_role, vpc=dev_vpc,
            vpc_subnets=ec2.SubnetSelection(subnets=dev_vpc.private_subnets),
            security_groups=[dev_sg],
            environment={"ANALYTICS_BUCKET": names["analytics"], "REGION": analytics_region,
                         "ENVIRONMENT": "dev"},
            log_group=function_logs("DevProcessorLogGroup", dev_name))

        loader_role = role("ConfigLoaderRole", "quartz-beta-config-loader",
                           iam.ManagedPolicy.from_aws_managed_policy_name(
                               "service-role/AWSLambdaBasicExecutionRole"))
        loader_role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[f"{config_bucket.bucket_arn}/*", f"{temp_bucket.bucket_arn}/*"]))
        loader_role.add_to_policy(iam.PolicyStatement(actions=["kms:Decrypt"], resources=["*"]))
        loader_name = f"{prefix}-config-loader-beta"
        loader = lambda_.Function(
            self, "ConfigLoader", function_name=loader_name, runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler", code=asset("config-loader"), timeout=Duration.seconds(60),
            memory_size=256, role=loader_role,
            environment={"CONFIG_BUCKET": config_bucket.bucket_name,
                         "TEMP_BUCKET": temp_bucket.bucket_name, "REGION": self.region},
            log_group=function_logs("ConfigLoaderLogGroup", loader_name))

        export(self, "LambdaFunctionName", reconciliation.function_name)
        export(self, "LambdaFunctionArn", reconciliation.function_arn)
        export(self, "LambdaRoleArn", reconciliation_role.role_arn)
        export(self, "LogGroupName", reconciliation_logs.log_group_name)
        export(self, "InputQueueUrl", input_queue.queue_url)
        export(self, "OutputQueueUrl", output_queue.queue_url)
        export(self, "MainVpcId", main_vpc.vpc_id)
        export(self, "ConfigLoaderFunctionName", loader.function_name)
        export(self, "WestKmsKeyArn", west_key.key_arn)


class TeamLogsStack(cdk.Stack):
    """A runtime log group and a role allowed to read some log groups and denied others."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        logs.LogGroup(self, "OnyxRuntimeLogGroup",
                      log_group_name=f"/aws/bedrock-agentcore/runtimes/{prefix}-onyx-basalt-DEFAULT",
                      retention=logs.RetentionDays.ONE_WEEK, removal_policy=RemovalPolicy.DESTROY)
        role = iam.Role(self, "QuartzTeamRole", role_name=f"{prefix}-quartz-team",
                        assumed_by=iam.ServicePrincipal("sts.amazonaws.com"),
                        description="Role for reading Bedrock AgentCore logs and runtime metadata")
        group = f"arn:{self.partition}:logs:{self.region}:{self.account}:log-group:"
        role.attach_inline_policy(iam.Policy(
            self, "CloudWatchLogsReadPolicy", policy_name="CloudWatchLogsReadPolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["logs:DescribeLogGroups", "logs:FilterLogEvents",
                             "logs:GetLogEvents"],
                    resources=[f"{group}/aws/bedrock-agentcore/*", f"{group}/aws/lambda/*",
                               f"{group}/aws/batch/*"]),
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["logs:FilterLogEvents", "logs:GetLogEvents"],
                    resources=[
                        f"{group}/aws/vendedlogs/bedrock-agentcore/runtime/APPLICATION_LOGS/*",
                        f"{group}/aws/vendedlogs/bedrock-agentcore/runtime/USAGE_LOGS/*"]),
            ]))
        role.attach_inline_policy(iam.Policy(
            self, "BedrockReadPolicy", policy_name="BedrockAgentReadPolicy",
            statements=[iam.PolicyStatement(
                actions=["bedrock-agent:ListAgents", "bedrock-agent:GetAgent"],
                resources=["*"])]))
        runtime = f"{prefix}-mcp"
        export(self, "QuartzTeamRoleArn", role.role_arn)
        export(self, "BasaltMcpLogGroupName", f"/aws/bedrock-agentcore/runtimes/{runtime}-DEFAULT")
        export(self, "BasaltMcpApplicationLogsGroupName",
               f"/aws/vendedlogs/bedrock-agentcore/runtime/APPLICATION_LOGS/{runtime}")
        export(self, "BasaltMcpUsageLogsGroupName",
               f"/aws/vendedlogs/bedrock-agentcore/runtime/USAGE_LOGS/{runtime}")


class MotionDetectionStack(cdk.Stack):
    """A Fargate service publishing latency metrics and traces, a backfill function, an alarm."""

    def __init__(self, scope, construct_id, *, prefix: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        # A VPC of its own with private subnets, rather than the account's default VPC, so the
        # task runs without a public address.
        vpc = ec2.Vpc(
            self, "ServiceVpc", vpc_name=f"{prefix}-motion-vpc",
            ip_addresses=ec2.IpAddresses.cidr("10.40.0.0/16"), max_azs=2, nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=24, name="Public",
                                        subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=24, name="Private",
                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ])
        task_logs = logs.LogGroup(self, "TaskLogGroup",
                                  log_group_name=f"{prefix}-motion-detection-{self.region}",
                                  retention=logs.RetentionDays.FOUR_MONTHS,
                                  removal_policy=RemovalPolicy.DESTROY)
        cluster = ecs.Cluster(self, "FlintMotionDetectionCluster",
                              cluster_name=f"{prefix}-motion-detection", vpc=vpc,
                              container_insights=True)
        execution_role = iam.Role(
            self, "TaskExecutionRole", assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AmazonECSTaskExecutionRolePolicy")])
        task_role = iam.Role(self, "TaskRole",
                             assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"))
        latency_mode = ssm.StringParameter(
            self, "QuartzLatencyMode", parameter_name=f"/{prefix}/flint/prod/quartz-latency-mode",
            string_value="healthy",
            description="Controls simulated Quartz API latency mode for the motion detection "
                        "service")
        publish_metrics = ssm.StringParameter(
            self, "PublishDependencyMetrics",
            parameter_name=f"/{prefix}/flint/prod/publish-dependency-metrics",
            string_value="true",
            description="Controls whether Flint/Dependencies Quartz API latency metrics are "
                        "published")
        task_role.add_to_policy(iam.PolicyStatement(actions=["cloudwatch:PutMetricData"],
                                                    resources=["*"]))
        task_role.add_to_policy(iam.PolicyStatement(
            actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords"], resources=["*"]))
        task_role.add_to_policy(iam.PolicyStatement(
            actions=["ssm:GetParameter"],
            resources=[latency_mode.parameter_arn, publish_metrics.parameter_arn]))
        definition = ecs.FargateTaskDefinition(
            self, "MotionDetectionTaskDefinition", family=f"{prefix}-motion-detection",
            cpu=256, memory_limit_mib=512, task_role=task_role, execution_role=execution_role)
        definition.add_container(
            "HLSProcess", container_name="HLSProcess",
            image=ecs.ContainerImage.from_asset(str(_ASSETS / "motion-detection-task")),
            cpu=256, memory_limit_mib=512, essential=True,
            logging=ecs.LogDrivers.aws_logs(stream_prefix="HLSProcess/container",
                                            log_group=task_logs),
            environment={"AWS_REGION": self.region, "CLUSTER_NAME": "Basalt", "STAGE": "prod",
                         "QUARTZ_LATENCY_MODE_PARAM": latency_mode.parameter_name,
                         "PUBLISH_DEP_METRICS_PARAM": publish_metrics.parameter_name})
        service_sg = ec2.SecurityGroup(
            self, "FargateSecurityGroup", vpc=vpc,
            description="Security group for Flint motion detection Fargate tasks",
            allow_all_outbound=True)
        service = ecs.FargateService(
            self, "MotionDetectionService", service_name=f"{prefix}-motion-detection",
            cluster=cluster, task_definition=definition, desired_count=1,
            assign_public_ip=False, security_groups=[service_sg],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            platform_version=ecs.FargatePlatformVersion.LATEST)

        backfill_dlq = sqs.Queue(self, "QuartzBackfillDlq",
                                 queue_name=f"{prefix}-quartzBackfillQueueDlq",
                                 retention_period=Duration.days(14), enforce_ssl=True,
                                 removal_policy=RemovalPolicy.DESTROY)
        backfill_queue = sqs.Queue(
            self, "QuartzBackfillQueue", queue_name=f"{prefix}-quartzBackfillQueue",
            dead_letter_queue=sqs.DeadLetterQueue(queue=backfill_dlq, max_receive_count=3),
            retention_period=Duration.days(14), enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY)
        backfill = lambda_.Function(
            self, "QuartzBackfillFunction", function_name=f"{prefix}-QuartzBackfill",
            runtime=lambda_.Runtime.PYTHON_3_11, handler="index.lambda_handler",
            code=asset("quartz-backfill"), memory_size=1280, timeout=Duration.minutes(5),
            environment={"QUARTZ_BACKFILL_QUEUE": backfill_queue.queue_name,
                         "QUARTZ_BACKFILL_DLQ": backfill_dlq.queue_name,
                         "STAGE": "prod", "CLUSTER": "Basalt"},
            log_retention=logs.RetentionDays.FOUR_MONTHS)
        backfill_queue.grant_consume_messages(backfill)
        backfill_dlq.grant_consume_messages(backfill)
        rule = events.Rule(self, "QuartzBackfillSchedule",
                           schedule=events.Schedule.rate(Duration.minutes(5)))
        rule.add_target(events_targets.LambdaFunction(
            backfill, event=events.RuleTargetInput.from_object(
                {"isPulling": "True", "queueName": backfill_dlq.queue_name})))

        def time_metric(operation: str, label: str) -> cloudwatch.Metric:
            return cloudwatch.Metric(namespace="Flint", metric_name="Time",
                                     dimensions_map={"Camera_name": "ALL",
                                                     "Operation": operation},
                                     statistic="p90", period=Duration.minutes(1), label=label)

        alarm = cloudwatch.Alarm(
            self, "ServiceLatencyAlarm", alarm_name=f"{prefix}-flint-prod-service-latency",
            alarm_description="P90 time, in milliseconds, from initial frame processing to "
                              "reporting an object to Quartz",
            metric=cloudwatch.Metric(namespace="Flint", metric_name="Time",
                                     dimensions_map={"Camera_name": "ALL",
                                                     "Operation": "FrameQuartzLag"},
                                     statistic="p90", period=Duration.minutes(1),
                                     unit=cloudwatch.Unit.MILLISECONDS),
            threshold=15000, evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING)
        frame_lag = time_metric("FrameQuartzLag", "FrameQuartzLag (P90)")
        internal = time_metric("InternalPipelineTime", "Internal Pipeline Time (P90)")
        quartz_latency = cloudwatch.Metric(
            namespace="Flint/Dependencies", metric_name="APILatency",
            dimensions_map={"Service": "Quartz", "Operation": "ReportPerson"},
            statistic="Average", period=Duration.minutes(1), label="Quartz API Latency (Avg)")
        cpu = cloudwatch.Metric(namespace="Flint", metric_name="NonIdlePct",
                                dimensions_map={"Camera_name": "ALL", "Operation": "CPU"},
                                statistic="p90", period=Duration.minutes(1),
                                label="CPU Utilization (P90)")
        dashboard = cloudwatch.Dashboard(self, "FlintMotionDetectionDashboard",
                                         dashboard_name=f"{prefix}-motion-detection-{self.region}")
        dashboard.add_widgets(cloudwatch.GraphWidget(
            title="End-to-End Latency vs Threshold", left=[frame_lag],
            left_annotations=[cloudwatch.HorizontalAnnotation(
                value=15000, label="Alarm Threshold (15s)", color=cloudwatch.Color.RED)],
            width=24, height=6))
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Internal Pipeline Components",
                left=[time_metric("ProcessFrame", "ProcessFrame (P90)"),
                      time_metric("MotionDetection", "MotionDetection (P90)"),
                      time_metric("HLSStartLag", "HLSStartLag (P90)"), internal],
                width=12, height=6),
            cloudwatch.GraphWidget(
                title="External Dependency Latency", left=[quartz_latency],
                left_annotations=[cloudwatch.HorizontalAnnotation(
                    value=15000, label="Expected Max (15s)", color=cloudwatch.Color.ORANGE)],
                width=12, height=6))
        dashboard.add_widgets(cloudwatch.GraphWidget(
            title="Latency Breakdown: Internal vs External", left=[internal],
            right=[quartz_latency], width=24, height=6))
        dashboard.add_widgets(
            cloudwatch.GraphWidget(title="ECS Service Health", left=[cpu], width=12, height=6),
            cloudwatch.SingleValueWidget(title="Service Latency Alarm Status",
                                         metrics=[frame_lag], width=12, height=6))

        export(self, "ClusterName", cluster.cluster_name)
        export(self, "ServiceName", service.service_name)
        export(self, "TaskLogGroupName", task_logs.log_group_name)
        export(self, "TaskDefinitionArn", definition.task_definition_arn)
        export(self, "QuartzLatencyModeParamName", latency_mode.parameter_name)
        export(self, "PublishDepMetricsParamName", publish_metrics.parameter_name)
        export(self, "QuartzBackfillFunctionName", backfill.function_name)
        export(self, "QuartzBackfillFunctionArn", backfill.function_arn)
        export(self, "QuartzBackfillQueueUrl", backfill_queue.queue_url)
        export(self, "QuartzBackfillDlqUrl", backfill_dlq.queue_url)
        export(self, "QuartzBackfillDlqName", backfill_dlq.queue_name)
        export(self, "ServiceLatencyAlarmName", alarm.alarm_name)
        export(self, "ServiceLatencyAlarmArn", alarm.alarm_arn)
        export(self, "DashboardName", dashboard.dashboard_name)


def build(app: cdk.App) -> None:
    """Every stack of the estate in its region, with the cross-stack orderings the app needs."""
    ctx = app.node.try_get_context
    account, prefix = ctx("account"), ctx("prefix")

    def kw(region_key: str) -> dict:
        # A synthesizer binds to one stack, so each stack gets its own.
        return {"env": cdk.Environment(account=account, region=ctx(region_key)),
                "synthesizer": cdk.DefaultStackSynthesizer(qualifier=ctx("qualifier"))}

    def name(part: str) -> str:
        return f"{prefix}-{part}"

    east = ctx("east")
    analytics = {"analytics": f"{prefix}-quartz-analytics-beta-{east}",
                 "archive": f"{prefix}-quartz-analytics-archive-{east}",
                 "reports": f"{prefix}-quartz-analytics-reports-{east}"}

    AppRolesStack(app, name("AppRoles"), prefix=prefix, **kw("east"))
    TenantOnlyDistributionStack(app, name("TenantOnlyCdn"), prefix=prefix, **kw("east"))
    RedshiftStack(app, name("Redshift"), prefix=prefix, **kw("east"))
    OrchestratorStack(app, name("Orchestrator"), prefix=prefix, **kw("east"))
    slr = OpenSearchSlrStack(app, name("OpenSearchSlr"), **kw("east"))
    for search in (CognitoSearchStack(app, name("CognitoSearch"), prefix=prefix, **kw("east")),
                   AuditedSearchStack(app, name("AuditedSearch"), prefix=prefix, **kw("east")),
                   StaleTargetsSearchStack(app, name("StaleTargetsSearch"), prefix=prefix,
                                           **kw("east"))):
        search.add_dependency(slr)
    knowledge = KnowledgeBaseStack(app, name("KnowledgeBases"), prefix=prefix, **kw("east"))
    AssistantConfigStack(app, name("AssistantConfig"), prefix=prefix,
                         kb_stack_name=knowledge.stack_name,
                         **kw("east")).add_dependency(knowledge)
    QuartzNlbStack(app, name("QuartzNlb"), prefix=prefix, **kw("east"))
    MainVpcStack(app, name("MainVpc"), prefix=prefix, **kw("west"))
    WebSocketStack(app, name("WebSocket"), prefix=prefix, **kw("east"))
    TigrisServiceStack(app, name("TigrisService"), prefix=prefix, **kw("east"))
    AgreementsApiStack(app, name("AgreementsApi"), prefix=prefix, **kw("east"))
    MotionDetectionStack(app, name("MotionDetection"), prefix=prefix, **kw("apse"))
    StreamManagerStack(app, name("StreamManager"), prefix=prefix, **kw("east"))
    OnyxStack(app, name("Onyx"), prefix=prefix, **kw("east"))
    TeamLogsStack(app, name("TeamLogs"), prefix=prefix, **kw("west"))
    DeploymentStatusStack(app, name("DeploymentStatus"), prefix=prefix, **kw("east"))
    TenantProvisioningStack(app, name("TenantProvisioning"), prefix=prefix, **kw("east"))
    buckets = AnalyticsBucketsStack(app, name("AnalyticsBuckets"), names=analytics, **kw("east"))
    ReconciliationStack(app, name("Reconciliation"), prefix=prefix, analytics_region=east,
                        names=analytics, **kw("west")).add_dependency(buckets)


app = cdk.App()
# Each VPC's zone lookup is answered from context, so synth makes no AWS call.
for _region, _zones in (
    (app.node.try_get_context("east"), app.node.try_get_context("azs_east")),
    (app.node.try_get_context("west"), app.node.try_get_context("azs_west")),
    (app.node.try_get_context("apse"), app.node.try_get_context("azs_apse")),
):
    app.node.set_context(
        f"availability-zones:account={app.node.try_get_context('account')}:region={_region}",
        _zones.split(","),
    )
build(app)
app.synth()
