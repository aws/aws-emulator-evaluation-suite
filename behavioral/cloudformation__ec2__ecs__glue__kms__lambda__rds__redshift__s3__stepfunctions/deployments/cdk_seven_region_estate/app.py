#!/usr/bin/env python3
"""A thirty-two-stack estate across several regions, much of it deliberately misconfigured.

Every stack stands alone. Nothing is reachable from outside its VPC: load balancers are internal,
no security group admits 0.0.0.0/0, nothing launches with a public IP, databases and clusters are
private and every bucket blocks public access.

Context:
  account, prefix -- the account; stack ids are "<prefix>-<Part>" and every name starts with prefix
  qualifier       -- bootstrap qualifier in every region
  regions         -- "<Part>=<region>;...", the region each stack deploys to
  azs             -- "<region>=<zone>,<zone>;...", every region's zones for the VPCs' lookups
  s3-prefix-list  -- the S3 managed prefix list id in the cluster NLB's region
  lf-admin-arn    -- the IAM principal made a data lake admin beside the CFN execution role
"""
import json

import aws_cdk as cdk
from aws_cdk import Duration, RemovalPolicy
from aws_cdk import aws_appconfig as appconfig
from aws_cdk import aws_autoscaling as autoscaling
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticache as elasticache
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_emr as emr
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_glue as glue
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lakeformation as lakeformation
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_lambda_event_sources as event_sources
from aws_cdk import aws_logs as logs
from aws_cdk import aws_networkfirewall as networkfirewall
from aws_cdk import aws_rds as rds
from aws_cdk import aws_redshift as redshift
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from aws_cdk import aws_wafv2 as wafv2

DESTROY = RemovalPolicy.DESTROY
PUBLIC, PRIVATE, ISOLATED = (ec2.SubnetType.PUBLIC, ec2.SubnetType.PRIVATE_WITH_EGRESS,
                             ec2.SubnetType.PRIVATE_ISOLATED)
#: Private ranges stand in for the corporate prefix lists the security groups admit SSH from.
CORPORATE_RANGES = ("10.0.0.0/20", "10.0.16.0/23")


def export(stack: cdk.Stack, name: str, value: str, description: str | None = None) -> None:
    """An output exported as "<stack name>-<name>"."""
    cdk.CfnOutput(stack, name, value=value, export_name=f"{stack.stack_name}-{name}",
                  description=description)


def exports(stack: cdk.Stack, **outputs: str | tuple[str, str]) -> None:
    """Outputs exported as by `export`, each a value or a (value, description) pair."""
    for name, output in outputs.items():
        export(stack, name, *(output if isinstance(output, tuple) else (output,)))


def secure_bucket(scope, construct_id: str, *, bucket_name: str, **kwargs) -> s3.Bucket:
    """A private, TLS-only bucket deleted with its objects; SSE-S3 unless told otherwise."""
    kwargs.setdefault("encryption", s3.BucketEncryption.S3_MANAGED)
    return s3.Bucket(
        scope, construct_id,
        bucket_name=bucket_name,
        removal_policy=DESTROY,
        auto_delete_objects=True,
        enforce_ssl=True,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        **kwargs,
    )


def written_by(bucket: s3.Bucket, *writers) -> None:
    """Delete each writer before the bucket's auto-delete handler empties the bucket.

    A stack delete removes a resource before what it depends on, so the writer depends on the
    handler; otherwise the writer refills the bucket after it is emptied.
    """
    handler = bucket.node.find_child("AutoDeleteObjectsCustomResource")
    for writer in writers:
        writer.node.add_dependency(handler)


def subnets(*groups: tuple[str, ec2.SubnetType, int]) -> list[ec2.SubnetConfiguration]:
    """Subnet groups ``(name, type, cidr mask)``; no subnet maps a public IP onto a launch."""
    return [
        ec2.SubnetConfiguration(
            name=name, subnet_type=subnet_type, cidr_mask=mask,
            map_public_ip_on_launch=False if subnet_type == PUBLIC else None,
        )
        for name, subnet_type, mask in groups
    ]


def _managed(name: str) -> iam.IManagedPolicy:
    """An AWS managed policy."""
    return iam.ManagedPolicy.from_aws_managed_policy_name(name)


def _service(name: str) -> iam.ServicePrincipal:
    """The service principal ``<name>.amazonaws.com``."""
    return iam.ServicePrincipal(f"{name}.amazonaws.com")


def make_vpc(scope, construct_id: str, *groups: tuple[str, ec2.SubnetType, int],
             cidr: str | None = None, **kwargs) -> ec2.Vpc:
    """A VPC of the subnet groups ``(name, type, cidr mask)``, in ``cidr`` when one is given."""
    return ec2.Vpc(scope, construct_id, subnet_configuration=subnets(*groups),
                   ip_addresses=ec2.IpAddresses.cidr(cidr) if cidr else None, **kwargs)


def select(subnet_type: ec2.SubnetType) -> ec2.SubnetSelection:
    """The subnets of one type."""
    return ec2.SubnetSelection(subnet_type=subnet_type)


def prefix_list(scope, construct_id: str, name: str,
                cidrs: tuple[str, ...] = CORPORATE_RANGES) -> ec2.IPeer:
    """A customer-managed prefix list of private ranges, as a security-group peer."""
    plist = ec2.CfnPrefixList(
        scope, construct_id,
        prefix_list_name=name,
        address_family="IPv4",
        max_entries=len(cidrs),
        entries=[ec2.CfnPrefixList.EntryProperty(cidr=c, description="private range")
                 for c in cidrs],
    )
    return ec2.Peer.prefix_list(plist.attr_prefix_list_id)


_STUB_HANDLER = """
def handler(event, context):
    return {
        'statusCode': 200,
        'body': 'success'
    }
"""

_ETL_SCRIPT = (
    "from awsglue.utils import getResolvedOptions\n"
    "from awsglue.context import GlueContext\n"
    "from pyspark.context import SparkContext\n"
    "import sys\n"
    'args = getResolvedOptions(sys.argv, ["database", "table"])\n'
    "sc = SparkContext()\n"
    "glueContext = GlueContext(sc)\n"
    'dyf = glueContext.create_dynamic_frame.from_catalog(database=args["database"], '
    'table_name=args["table"])\n'
    "print(dyf.count())\n"
)


def app_roles(s: cdk.Stack, *, prefix: str) -> None:
    """A read-only and an operator role assumable from the account, and Bedrock's service role."""
    vectors_read_only = iam.ManagedPolicy(
        s, "S3VectorsReadOnlyAccess",
        managed_policy_name=f"{prefix}-s3vectors-ro",
        description="Read-only access to S3 Vectors operations",
        statements=[iam.PolicyStatement(
            sid="AllowS3VectorsReadOnlyAccess",
            actions=[
                "s3vectors:ListVectors", "s3vectors:GetVectors", "s3vectors:GetIndex",
                "s3vectors:GetVectorBucket", "s3vectors:GetVectorBucketPolicy",
                "s3vectors:ListIndexes", "s3vectors:ListTagsForResource",
                "s3vectors:ListVectorBuckets", "s3vectors:QueryVectors",
            ],
            resources=["*"],
        )],
    )
    managed = iam.ManagedPolicy.from_aws_managed_policy_name
    account = iam.AccountPrincipal(s.account)
    iam.Role(s, "ApplicationReadOnlyRole", role_name=f"{prefix}-app-readonly",
             assumed_by=account,
             managed_policies=[managed("ReadOnlyAccess"),
                               managed("AmazonS3TablesReadOnlyAccess"),
                               vectors_read_only])
    # The operator role reads the account; it is never granted write or administrator access.
    iam.Role(s, "ApplicationAdminRole", role_name=f"{prefix}-app-operator",
             assumed_by=account, managed_policies=[managed("ReadOnlyAccess")])
    # Bedrock's service role: nothing in the estate invokes a model, so it holds no policy.
    iam.Role(s, "BedrockServiceAccessRole", role_name=f"{prefix}-app-bedrock",
             assumed_by=_service("bedrock"))


def alias_functions(s: cdk.Stack, *, prefix: str) -> None:
    """Two traced functions, each behind a LATEST alias on its published version."""
    s.template_options.description = "CloudFormation stacks with Lambda alias deployments"
    bucket = secure_bucket(s, "DeploymentBucket", bucket_name=f"{prefix}-deploy-artifacts")
    managed = iam.ManagedPolicy.from_aws_managed_policy_name

    functions = {}
    for key, name, version in (("SimpleEmailService", "SimpleEmailService", "1764962361325"),
                               ("GetDetectorOutcome", "GetDetectorOutcome", "1764962361401")):
        role = iam.Role(s, f"{key}LambdaRole", role_name=f"{prefix}-{name}-role",
                        assumed_by=_service("lambda"),
                        managed_policies=[
                            managed("service-role/AWSLambdaBasicExecutionRole"),
                            managed("AWSXRayDaemonWriteAccess")])
        log_group = logs.LogGroup(s, f"{key}LogGroup",
                                  log_group_name=f"{prefix}-{name}-LogGroup",
                                  retention=logs.RetentionDays.TEN_YEARS,
                                  removal_policy=DESTROY)
        fn = lambda_.Function(
            s, f"{key}Lambda",
            function_name=f"{prefix}-{name}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(_STUB_HANDLER),
            role=role,
            memory_size=1024,
            timeout=Duration.seconds(900),
            tracing=lambda_.Tracing.ACTIVE,
            log_group=log_group,
            environment={
                "ENGINE_ENDPOINT": "https://engine-api.internal/Engine-APIGateway",
                "STS_ENDPOINT": f"sts.{s.region}.amazonaws.com",
                "domain": "prod",
                "SQS_ENDPOINT": f"sqs.{s.region}.amazonaws.com",
                "PARTITION": "aws",
                "region": s.region,
                "version": version,
                "REGION_STATUS": "active",
            },
        )
        alias = lambda_.Alias(s, f"{key}LambdaAlias", alias_name="LATEST",
                              version=fn.current_version)
        functions[key] = (fn, alias)

    # The change-set execution role may move the aliases and nothing else.
    exec_role = iam.Role(s, "PipelinesChangeSetExecRole",
                         role_name=f"{prefix}-changeset-exec",
                         assumed_by=_service("cloudformation"))
    exec_role.add_to_policy(iam.PolicyStatement(
        actions=["lambda:GetAlias", "lambda:UpdateAlias", "lambda:GetFunction"],
        resources=[arn for fn, _ in functions.values()
                   for arn in (fn.function_arn, f"{fn.function_arn}:*")],
    ))

    export(s, "DeploymentBucketName", bucket.bucket_name)
    for key, (fn, alias) in functions.items():
        export(s, f"{key}LambdaArn", fn.function_arn)
        export(s, f"{key}LambdaAliasArn", alias.function_arn)
        export(s, f"{key}LambdaAliasLogicalId", s.get_logical_id(alias.node.default_child))
        export(s, f"{key}LambdaName", fn.function_name)
    exports(
        s,
        CloudFormationExecutionRoleArn=exec_role.role_arn,
    )


def flow_log_vpc(s: cdk.Stack, *, prefix: str) -> None:
    """A VPC whose single flow log delivers to S3, beside two log groups no flow log writes."""
    vpc = make_vpc(s, "BasaltVPC", ("Public", PUBLIC, 24), cidr="10.2.0.0/16", max_azs=2,
                   nat_gateways=0)
    cdk.Tags.of(vpc).add("Name", f"{prefix}-BasaltVPC")
    cdk.Tags.of(vpc).add("Environment", "staging")

    bucket = secure_bucket(s, "VpcFlowLogsBucket", bucket_name=f"{prefix}-basalt-flowlogs")
    flow_log = ec2.FlowLog(s, "VpcFlowLog",
                           resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
                           destination=ec2.FlowLogDestination.to_s3(bucket),
                           traffic_type=ec2.FlowLogTrafficType.ALL)
    written_by(bucket, flow_log)
    cdk.Tags.of(flow_log).add("Basalt-Security-Managed", "VPCFlowLogs")
    cdk.Tags.of(flow_log).add("Name", "Do-Not-Delete-Basalt-VPCFlowLogs")

    # Left over from an earlier deployment: no flow log writes to either group.
    for index in (1, 2):
        logs.LogGroup(s, f"OrphanedVpcFlowLogGroup{index}",
                      log_group_name=f"{prefix}-QuartzStack-Basalt-VpcFlowLogLogGroup{index}",
                      retention=logs.RetentionDays.TWO_YEARS,
                      removal_policy=DESTROY)

    exports(
        s,
        VpcId=vpc.vpc_id,
        FlowLogId=flow_log.flow_log_id,
        VpcFlowLogsBucketName=bucket.bucket_name,
    )


def lake_formation_settings(s: cdk.Stack, *, qualifier: str, lf_admin_arn: str) -> None:
    """The account's data lake admins; its empty default lists leave the account's defaults."""
    exec_role = (f"arn:{s.partition}:iam::{s.account}:role/"
                 f"cdk-{qualifier}-cfn-exec-role-{s.account}-{s.region}")
    lakeformation.CfnDataLakeSettings(
        s, "DataLakeSettings",
        admins=[lakeformation.CfnDataLakeSettings.DataLakePrincipalProperty(
                    data_lake_principal_identifier=arn)
                for arn in (exec_role, lf_admin_arn)],
        create_database_default_permissions=[],
        create_table_default_permissions=[],
    )


def lake_formation_etl(s: cdk.Stack, *, prefix: str) -> None:
    """A Glue job, its role a Lake Formation data admin, reading a table with no LF grant."""
    script_bucket = secure_bucket(s, "ScriptBucket", bucket_name=f"{prefix}-basalt-scripts")
    script = s3deploy.BucketDeployment(
        s, "GlueScriptDeployment",
        sources=[s3deploy.Source.data("scripts/etl.py", _ETL_SCRIPT)],
        destination_bucket=script_bucket,
    )
    database_name = f"{prefix.replace('-', '_')}_quartz_basalt"
    database = glue.CfnDatabase(
        s, "GlueDatabase", catalog_id=s.account,
        # An explicit empty default, so no new table grants IAMAllowedPrincipals whatever
        # the account's data lake settings were when the database was created.
        database_input=glue.CfnDatabase.DatabaseInputProperty(
            name=database_name, description="Database for usage events data",
            create_table_default_permissions=[]))
    # The data location is a bucket this account neither owns nor registers.
    table = glue.CfnTable(
        s, "GlueTable", catalog_id=s.account, database_name=database.ref,
        table_input=glue.CfnTable.TableInputProperty(
            name="usage_events",
            description="Usage events data",
            table_type="EXTERNAL_TABLE",
            parameters={"classification": "parquet", "compressionType": "snappy",
                        "typeOfData": "file"},
            partition_keys=[glue.CfnTable.ColumnProperty(name="serviceid", type="string"),
                            glue.CfnTable.ColumnProperty(name="eventdate", type="date")],
            storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                columns=[glue.CfnTable.ColumnProperty(name=n, type=t) for n, t in (
                    ("accountarn", "string"), ("accountid", "string"),
                    ("accountname", "string"), ("eventname", "string"),
                    ("eventtype", "string"), ("timestamp", "bigint"),
                    ("consoleregion", "string"))],
                location=f"s3://{prefix}-partitioned-data-elsewhere/usage_events/",
                input_format="org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                output_format=(
                    "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"),
                serde_info=glue.CfnTable.SerdeInfoProperty(
                    serialization_library=(
                        "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"),
                    parameters={"serialization.format": "1"}),
                compressed=True,
            ),
        ),
    )
    table.node.add_dependency(database)
    managed = iam.ManagedPolicy.from_aws_managed_policy_name
    # AWSLakeFormationDataAdmin makes Glue vend Lake Formation credentials for the table; the
    # role reads only its script and the table's data location.
    role = iam.Role(s, "GlueServiceRole", role_name=f"{prefix}-glue-service-default",
                    assumed_by=_service("glue"),
                    managed_policies=[managed("service-role/AWSGlueServiceRole"),
                                      managed("AWSLakeFormationDataAdmin")])
    script_bucket.grant_read(role)
    elsewhere = f"arn:{s.partition}:s3:::{prefix}-partitioned-data-elsewhere"
    role.add_to_policy(iam.PolicyStatement(actions=["s3:ListBucket"], resources=[elsewhere]))
    role.add_to_policy(iam.PolicyStatement(actions=["s3:GetObject"],
                                           resources=[f"{elsewhere}/usage_events/*"]))
    job = glue.CfnJob(
        s, "GlueJob",
        name=f"{prefix}-usage-events-load",
        role=role.role_arn,
        command=glue.CfnJob.JobCommandProperty(
            name="glueetl", python_version="3",
            script_location=f"s3://{script_bucket.bucket_name}/scripts/etl.py"),
        glue_version="4.0",
        worker_type="G.1X",
        number_of_workers=2,
        timeout=10,
        max_retries=0,
        default_arguments={"--database": database.ref, "--table": table.ref},
    )
    job.node.add_dependency(script)
    job.node.add_dependency(table)

    exports(
        s,
        GlueDatabaseName=database.ref,
        GlueTableName=table.ref,
        GlueJobName=job.ref,
        GlueServiceRoleArn=role.role_arn,
    )


#: Object keys each stream consumer may read, under both clickstream buckets.
_STREAM_PATTERNS = {
    "basalt": (
        "data/region=*/name=devices-flint/*",
        "manifest/region=*/name=devices-flint/*",
        "data/region=*/name=clickstream-event-pt1h/*",
        "manifest/region=*/name=clickstream-event-pt1h/*",
        "*/clickstream-flint-*/*",
        "*/clickstream-pflint-undecorated-basalt-*/*",
    ),
    "onyx": (
        "data/region=*/name=devices-*-onyx/*",
        "manifest/region=*/name=devices-*-onyx/*",
        "data/region=*/name=clickstream-event-onyx-pt1h/*",
        "manifest/region=*/name=clickstream-event-onyx-pt1h/*",
        "*/clickstream-flint-onyx-*/*",
        "*/clickstream-flint-ops-onyx-*/*",
        "*/clickstream-pflint-undecorated-onyx-*/*",
    ),
}

#: The seeded objects: one under no consumer's patterns, one under the basalt consumer's.
SEED_OBJECTS = {
    "data/test-object.json": {"event": "test"},
    "data/region=us-east-1/name=devices-flint/sample.json": {"event": "sample"},
}

_WORK_RUNNER_QUEUES = (
    "quartz-work-runner-queue", "quartz-work-runner-backfill-queue", "quartz-work-runner-dlq",
    "quartz-work-runner-onhold-queue", "devices-flint-work-runner-queue",
    "devices-flint-work-runner-backfill-queue", "devices-flint-work-runner-dlq",
    "devices-flint-work-runner-onhold-queue", "clickstream-flint-work-runner-queue",
)

#: On delete, revokes the group-to-group rules EMR added to its managed security groups, which
#: otherwise reference each other and keep CloudFormation from deleting the groups.
_RULE_REVOKER = """
import boto3
import cfnresponse


def _pairs_only(permissions):
    out = []
    for p in permissions:
        if p.get("UserIdGroupPairs"):
            keep = {k: p[k] for k in ("IpProtocol", "FromPort", "ToPort") if k in p}
            keep["UserIdGroupPairs"] = [{"GroupId": g["GroupId"]} for g in p["UserIdGroupPairs"]]
            out.append(keep)
    return out


def handler(event, context):
    try:
        if event["RequestType"] == "Delete":
            ec2 = boto3.client("ec2")
            ids = event["ResourceProperties"]["GroupIds"]
            for group in ec2.describe_security_groups(GroupIds=ids)["SecurityGroups"]:
                ingress = _pairs_only(group["IpPermissions"])
                egress = _pairs_only(group["IpPermissionsEgress"])
                if ingress:
                    ec2.revoke_security_group_ingress(GroupId=group["GroupId"],
                                                      IpPermissions=ingress)
                if egress:
                    ec2.revoke_security_group_egress(GroupId=group["GroupId"],
                                                     IpPermissions=egress)
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
    except Exception as exc:
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, reason=str(exc)[:200])
"""


def clickstream_data(s: cdk.Stack, *, prefix: str) -> None:
    """KMS-encrypted clickstream buckets read by stream consumers and legacy roles, and a queue
    consumer function.

    The key policy names no data-plane principal; the consumers are added to it after deploy and
    the legacy roles never are, so their reads are refused by KMS despite their IAM grants.
    """
    key = kms.Key(
        s, "QuartzKmsKey",
        enable_key_rotation=True,
        description="KMS key for Quartz bucket encryption",
        alias=f"alias/{prefix}-quartz",
        removal_policy=DESTROY,
        policy=iam.PolicyDocument(statements=[iam.PolicyStatement(
            principals=[iam.AccountRootPrincipal()],
            actions=["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
                     "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
                     "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:TagResource",
                     "kms:UntagResource"],
            resources=["*"],
        )]),
    )
    access_logs = secure_bucket(s, "AccessLogsBucket", bucket_name=f"{prefix}-quartz-access-logs")
    expiring = [s3.LifecycleRule(enabled=True, expiration=Duration.days(30), prefix=p)
                for p in ("data/", "manifest/")]
    clickstream = secure_bucket(s, "ClickstreamBucket",
                                bucket_name=f"{prefix}-quartz-clickstream",
                                encryption=s3.BucketEncryption.KMS, encryption_key=key,
                                server_access_logs_bucket=access_logs,
                                lifecycle_rules=expiring)
    munged = secure_bucket(s, "MungedBucket",
                           bucket_name=f"{prefix}-quartz-clickstream-munged",
                           encryption=s3.BucketEncryption.KMS, encryption_key=key,
                           lifecycle_rules=expiring)
    emr_logs = secure_bucket(s, "EmrLogsBucket", bucket_name=f"{prefix}-emr-cluster-logs",
                             versioned=True,
                             lifecycle_rules=[s3.LifecycleRule(
                                 enabled=True, expiration=Duration.days(90))])
    both = [clickstream.bucket_arn, f"{clickstream.bucket_arn}/*",
            munged.bucket_arn, f"{munged.bucket_arn}/*"]
    managed = iam.ManagedPolicy.from_aws_managed_policy_name

    # EMR's processing role, named in the key policy once deployed: no cluster in this stack
    # assumes it, so it trusts only EMR and holds no policy.
    workhorse = iam.Role(
        s, "WorkhorseRole", role_name=f"{prefix}-quartz-workhorse",
        assumed_by=_service("elasticmapreduce"))
    # The operations instances' role: no instance in this stack uses it, so it holds nothing.
    iam.Role(s, "OperationsRole", role_name=f"{prefix}-operations-access",
             assumed_by=_service("ec2"))
    # The external readers' role reads the account and decrypts only the clickstream key.
    external = iam.Role(s, "ExternalAccessRole", role_name=f"{prefix}-external-access",
                        assumed_by=iam.AccountPrincipal(s.account),
                        managed_policies=[managed("ReadOnlyAccess")])
    external.add_to_policy(iam.PolicyStatement(actions=["kms:Decrypt"], resources=[key.key_arn]))

    stream_roles = {}
    for access, patterns in _STREAM_PATTERNS.items():
        title = access.capitalize()
        policy = iam.ManagedPolicy(
            s, f"ExternalAccess{title}Policy",
            managed_policy_name=f"{prefix}-stream-{access}-policy",
            statements=[
                iam.PolicyStatement(actions=["s3:ListBucket"],
                                    resources=[clickstream.bucket_arn, munged.bucket_arn]),
                iam.PolicyStatement(actions=["s3:GetObject"], resources=[
                    f"{bucket.bucket_arn}/{pattern}"
                    for pattern in patterns for bucket in (clickstream, munged)]),
                iam.PolicyStatement(actions=["kms:Decrypt"], resources=[key.key_arn]),
            ])
        stream_roles[access] = iam.Role(
            s, f"ExternalAccess{title}Role", role_name=f"{prefix}-stream-{access}",
            assumed_by=iam.AccountPrincipal(s.account), managed_policies=[policy])

    legacy_roles = {}
    for user in ("flint-s3-read", "cobalt"):
        role = iam.Role(s, f"LegacyUser{user.replace('-', '')}Role",
                        role_name=f"{prefix}-legacy-{user}",
                        assumed_by=iam.AccountPrincipal(s.account))
        role.add_to_policy(iam.PolicyStatement(actions=["s3:GetObject", "s3:ListBucket"],
                                               resources=both))
        role.add_to_policy(iam.PolicyStatement(actions=["kms:Decrypt"], resources=[key.key_arn]))
        legacy_roles[user] = role

    seed = s3deploy.BucketDeployment(
        s, "SeedClickstreamObject",
        sources=[s3deploy.Source.json_data(k, v) for k, v in SEED_OBJECTS.items()],
        destination_bucket=clickstream,
        prune=False,
        server_side_encryption=s3deploy.ServerSideEncryption.AWS_KMS,
        server_side_encryption_aws_kms_key_id=key.key_id,
    )
    # The key policy delegates nothing to IAM, so the seeding handler is named in it.
    key.add_to_resource_policy(iam.PolicyStatement(
        principals=[seed.handler_role], actions=["kms:GenerateDataKey", "kms:Decrypt"],
        resources=["*"]))

    vpc = make_vpc(s, "ApplicationVpc", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24),
                   vpc_name=f"{prefix}-application-vpc", max_azs=3, nat_gateways=1)

    dlq = sqs.Queue(s, "StreamTrackerDlq", queue_name=f"{prefix}-streamTrackerDlq",
                    retention_period=Duration.days(14))
    tracker = sqs.Queue(s, "StreamTrackerQueue", queue_name=f"{prefix}-streamTrackerQueue",
                        visibility_timeout=Duration.seconds(60),
                        dead_letter_queue=sqs.DeadLetterQueue(queue=dlq, max_receive_count=3))
    certifier_role = iam.Role(
        s, "CertifierLambdaRole", role_name=f"{prefix}-certifier-fn",
        assumed_by=_service("lambda"),
        managed_policies=[managed("service-role/AWSLambdaVPCAccessExecutionRole"),
                          managed("service-role/AWSLambdaBasicExecutionRole")])
    tracker.grant_consume_messages(certifier_role)
    certifier_logs = logs.LogGroup(s, "CertifierLambdaLogGroup", removal_policy=DESTROY)
    certifier = lambda_.Function(
        s, "CertifierLambda",
        log_group=certifier_logs,
        function_name=f"{prefix}-Certifier",
        runtime=lambda_.Runtime.PYTHON_3_12,
        handler="index.handler",
        code=lambda_.Code.from_inline("def handler(e, c): pass"),
        memory_size=512,
        timeout=Duration.seconds(60),
        role=certifier_role,
        vpc=vpc,
        vpc_subnets=select(PRIVATE),
        environment={"APP_NAME": "quartz-stream",
                     "APP_BUCKET_NAME": clickstream.bucket_name,
                     "APP_BUCKET_REGION": s.region, "STAGE": "prod"},
    )
    certifier.add_event_source(event_sources.SqsEventSource(tracker, batch_size=10))
    for name in _WORK_RUNNER_QUEUES:
        sqs.Queue(s, f"WorkRunner{name.replace('-', '')}", queue_name=f"{prefix}-{name}",
                  visibility_timeout=Duration.seconds(300),
                  retention_period=Duration.days(14))

    exports(
        s,
        ClickstreamBucketName=clickstream.bucket_name,
        MungedBucketName=munged.bucket_name,
        AccessLogsBucketName=access_logs.bucket_name,
        EmrLogsBucketName=emr_logs.bucket_name,
        KmsKeyId=key.key_id,
        KmsKeyArn=key.key_arn,
        WorkhorseRoleArn=workhorse.role_arn,
        WorkhorseRoleName=workhorse.role_name,
        StreamTrackerQueueUrl=tracker.queue_url,
        StreamTrackerDlqUrl=dlq.queue_url,
        CertifierLambdaArn=certifier.function_arn,
        CertifierLambdaName=certifier.function_name,
        VpcId=vpc.vpc_id,
        LegacyFlintRoleName=legacy_roles["flint-s3-read"].role_name,
        LegacyFlintRoleArn=legacy_roles["flint-s3-read"].role_arn,
        BasaltRoleName=stream_roles["basalt"].role_name,
        BasaltRoleArn=stream_roles["basalt"].role_arn,
        OnyxRoleName=stream_roles["onyx"].role_name,
        OnyxRoleArn=stream_roles["onyx"].role_arn,
    )


def redshift_clusters(s: cdk.Stack, *, prefix: str) -> None:
    """Two private single-node clusters and their alarms; one health alarm compares the wrong way.

    HealthStatus is 1 on a healthy cluster, and the all-nodes alarm fires when it is above 0.5.
    """
    vpc = make_vpc(s, "VPC", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24),
                   vpc_name=f"{prefix}-redshift-vpc", max_azs=2, nat_gateways=1)
    groups = [ec2.SecurityGroup(s, f"SecurityGroup{i}", vpc=vpc,
                                security_group_name=f"{prefix}-redshift-sg-{i}",
                                description=f"Security group {i} for Redshift clusters")
              for i in range(1, 6)]
    key = kms.Key(s, "RedshiftKMSKey", alias=f"alias/{prefix}-redshift-encryption-key",
                  description="KMS key for Redshift cluster encryption",
                  enable_key_rotation=True, removal_policy=DESTROY)
    s3_read = _managed("AmazonS3ReadOnlyAccess")
    spectrum_roles = [
        iam.Role(s, logical, role_name=f"{prefix}-{name}",
                 assumed_by=_service("redshift"),
                 managed_policies=[s3_read])
        for logical, name in (("SpectrumLakeFormationRole", "QuartzLakeFormationRole"),
                              ("FlintSpectrumRole", "QuartzFlintRole"),
                              ("BasaltSpectrumRole", "QuartzBasaltRole"))
    ]
    parameter_group = redshift.CfnClusterParameterGroup(
        s, "RedshiftParameterGroup",
        description="Parameter group for Redshift clusters",
        parameter_group_family="redshift-1.0",
        parameters=[redshift.CfnClusterParameterGroup.ParameterProperty(
            parameter_name=n, parameter_value=v) for n, v in (
            ("enable_user_activity_logging", "true"), ("require_ssl", "true"),
            ("use_fips_ssl", "false"), ("auto_analyze", "true"),
            ("max_concurrency_scaling_clusters", "1"),
            ("enable_case_sensitive_identifier", "false"), ("auto_mv", "true"))],
    )
    subnet_group = redshift.CfnClusterSubnetGroup(
        s, "RedshiftSubnetGroup", description="Subnet group for Redshift clusters",
        subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets])
    # The admin password is generated into a secret the Data API can sign in with.
    admin = secretsmanager.Secret(
        s, "RedshiftAdminSecret",
        secret_name=f"{prefix}-redshift-admin",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "quartz_etl"}),
            generate_string_key="password",
            password_length=32,
            exclude_characters="\"'\\/@ "),
    )

    clusters = {}
    for key_name, logical, identifier in (("Adhoc", "RedshiftClusterAdhoc", "adhoc1"),
                                          ("Global", "RedshiftClusterGlobal",
                                           "global-basalt1")):
        cluster = redshift.CfnCluster(
            s, logical,
            cluster_type="single-node",
            node_type="ra3.xlplus",
            db_name="quartzdb",
            master_username="quartz_etl",
            master_user_password=admin.secret_value_from_json("password").unsafe_unwrap(),
            cluster_identifier=f"{prefix}-quartz-{identifier}",
            cluster_subnet_group_name=subnet_group.ref,
            vpc_security_group_ids=[g.security_group_id for g in groups],
            cluster_parameter_group_name=parameter_group.ref,
            encrypted=True,
            kms_key_id=key.key_arn,
            publicly_accessible=False,
            enhanced_vpc_routing=False,
            automated_snapshot_retention_period=1,
            manual_snapshot_retention_period=-1,
            allow_version_upgrade=True,
            maintenance_track_name="trailing",
            preferred_maintenance_window="wed:04:00-wed:04:30",
            iam_roles=[r.role_arn for r in spectrum_roles],
            tags=[cdk.CfnTag(key="quartz-service", value="QuartzGarnet")],
        )
        cluster.node.add_dependency(parameter_group)
        cluster.node.add_dependency(subnet_group)
        clusters[key_name] = cluster

    topic = sns.Topic(s, "RedshiftCriticalTopic", topic_name=f"{prefix}-redshift-critical",
                      display_name="Redshift Production Critical Alarms")

    def metric(cluster, period, **dims):
        return cloudwatch.Metric(
            namespace="AWS/Redshift", metric_name=dims.pop("name"),
            dimensions_map={"ClusterIdentifier": cluster.cluster_identifier, **dims},
            statistic="Average", period=period)

    cpu = cloudwatch.Alarm(
        s, "AdhocCPUAlarm", alarm_name=f"{prefix}-adhoc1-CPUUtilization",
        metric=metric(clusters["Adhoc"], Duration.minutes(5), name="CPUUtilization"),
        threshold=95.0, evaluation_periods=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        actions_enabled=True)
    cpu.add_alarm_action(cloudwatch_actions.SnsAction(topic))
    health_all = cloudwatch.Alarm(
        s, "GlobalHealthAllAlarm", alarm_name=f"{prefix}-global-basalt1-HealthStatus-All",
        alarm_description=("Alarm for quartz-global-basalt1 when cluster is unhealthy for "
                           "more than 5 minutes"),
        metric=metric(clusters["Global"], Duration.minutes(5), name="HealthStatus"),
        threshold=0.5, evaluation_periods=1, datapoints_to_alarm=1,
        comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        actions_enabled=True)
    health_leader = cloudwatch.Alarm(
        s, "GlobalHealthLeaderAlarm",
        alarm_name=f"{prefix}-global-basalt1-HealthStatus-Leader",
        alarm_description=("Alarm for when quartz-global-basalt1 cluster's Leader Node is "
                           "unhealthy for more than 5 minutes"),
        metric=metric(clusters["Global"], Duration.minutes(30), name="HealthStatus",
                      NodeID="Leader"),
        threshold=1.0, evaluation_periods=1, datapoints_to_alarm=1,
        comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
        actions_enabled=True)

    export(s, "VpcId", vpc.vpc_id)
    for key_name, cluster in clusters.items():
        export(s, f"{key_name}ClusterIdentifier", cluster.cluster_identifier)
        export(s, f"{key_name}ClusterEndpoint", cluster.attr_endpoint_address)
    exports(
        s,
        AdminSecretArn=admin.secret_arn,
        KMSKeyId=key.key_id,
        SNSTopicArn=topic.topic_arn,
        AdhocCPUAlarmName=cpu.alarm_name,
        GlobalHealthAllAlarmName=health_all.alarm_name,
        GlobalHealthLeaderAlarmName=health_leader.alarm_name,
    )


def aurora_postgres(s: cdk.Stack, *, prefix: str) -> None:
    """A private Aurora PostgreSQL writer and reader with Performance Insights under its own key."""
    vpc = make_vpc(s, "VPC", ("Isolated", ISOLATED, 24), vpc_name=f"{prefix}-aurora-vpc", max_azs=2,
                   nat_gateways=0)
    group = ec2.SecurityGroup(s, "AuroraSecurityGroup", vpc=vpc,
                              description="Security group for Aurora PostgreSQL cluster",
                              security_group_name=f"{prefix}-aurora-sg")
    pi_key = kms.Key(s, "PerformanceInsightsKey",
                     description="KMS key for Aurora Performance Insights encryption",
                     enable_key_rotation=True, removal_policy=DESTROY)
    monitoring = iam.Role(
        s, "EnhancedMonitoringRole",
        assumed_by=_service("monitoring.rds"),
        description="IAM role for RDS Enhanced Monitoring",
        managed_policies=[_managed(
            "service-role/AmazonRDSEnhancedMonitoringRole")])
    isolated = select(ISOLATED)
    subnet_group = rds.SubnetGroup(s, "DBSubnetGroup",
                                   description="Subnet group for Aurora PostgreSQL cluster",
                                   vpc=vpc, vpc_subnets=isolated,
                                   subnet_group_name=f"{prefix}-basalt-db-subnets",
                                   removal_policy=DESTROY)
    engine = rds.DatabaseClusterEngine.aurora_postgres(
        version=rds.AuroraPostgresEngineVersion.of("17.4", "17"))
    parameter_group = rds.ParameterGroup(
        s, "ClusterParameterGroup", engine=engine,
        description="Parameter group for Aurora PostgreSQL cluster",
        removal_policy=DESTROY)

    def instance(name):
        return rds.ClusterInstance.provisioned(
            name, instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3,
                                                    ec2.InstanceSize.MEDIUM),
            publicly_accessible=False, promotion_tier=1, auto_minor_version_upgrade=False)

    identifier = f"{prefix}-basalt-postgres"
    cluster = rds.DatabaseCluster(
        s, "AuroraPostgreCluster",
        engine=engine,
        credentials=rds.Credentials.from_generated_secret("postgres"),
        writer=instance("writer"),
        readers=[instance("reader")],
        vpc=vpc, vpc_subnets=isolated,
        security_groups=[group],
        subnet_group=subnet_group,
        parameter_group=parameter_group,
        port=5432,
        backup=rds.BackupProps(retention=Duration.days(7), preferred_window="03:00-04:00"),
        preferred_maintenance_window="sun:04:00-sun:05:00",
        storage_encrypted=False,
        deletion_protection=False,
        cloudwatch_logs_exports=["postgresql"],
        cloudwatch_logs_retention=logs.RetentionDays.ONE_WEEK,
        monitoring_interval=Duration.seconds(60),
        monitoring_role=monitoring,
        enable_performance_insights=True,
        performance_insight_encryption_key=pi_key,
        performance_insight_retention=rds.PerformanceInsightRetention.LONG_TERM,
        iam_authentication=False,
        copy_tags_to_snapshot=False,
        removal_policy=DESTROY,
        cluster_identifier=identifier,
    )
    cdk.Tags.of(cluster).add("Name", identifier)

    exports(
        s,
        ClusterIdentifier=cluster.cluster_identifier,
        ClusterEndpoint=cluster.cluster_endpoint.hostname,
        ClusterReadEndpoint=cluster.cluster_read_endpoint.hostname,
        ClusterArn=cluster.cluster_arn,
        SecretArn=cluster.secret.secret_arn,
        SecurityGroupId=group.security_group_id,
        PerformanceInsightsKeyArn=pi_key.key_arn,
        MonitoringRoleArn=monitoring.role_arn,
    )


def role_report_job(s: cdk.Stack, *, prefix: str, home_region: str) -> None:
    """A Glue job whose script location names an object nothing uploads."""
    buckets = {}
    for logical, name in (("FlintDataBucket", "onyx-data"),
                          ("GlueAssetsBucket", "glue-assets"),
                          ("GlueLogsBucket", "glue-logs")):
        bucket = secure_bucket(s, logical, bucket_name=f"{prefix}-basalt-{name}-alpha")
        cdk.Tags.of(bucket).add("Environment", "alpha")
        cdk.Tags.of(bucket).add("Service", "basalt-data")
        buckets[logical] = bucket
    role = iam.Role(s, "GlueJobRole", role_name=f"{prefix}-basalt-glue-job",
                    assumed_by=_service("glue"),
                    managed_policies=[_managed(
                        "service-role/AWSGlueServiceRole")])
    buckets["GlueAssetsBucket"].grant_read(role)
    buckets["FlintDataBucket"].grant_read_write(role)
    buckets["GlueLogsBucket"].grant_write(role)
    assets, glue_logs = buckets["GlueAssetsBucket"], buckets["GlueLogsBucket"]
    job = glue.CfnJob(
        s, "BasaltDataAnalyzerJob",
        name=f"{prefix}-RoleReport",
        role=role.role_arn,
        command=glue.CfnJob.JobCommandProperty(
            name="glueetl", python_version="3",
            script_location=f"s3://{assets.bucket_name}/scripts/role_analyzer.py"),
        glue_version="4.0",
        max_retries=0,
        timeout=2880,
        default_arguments={
            "--enable-metrics": "true",
            "--enable-continuous-cloudwatch-log": "true",
            "--enable-continuous-log-filter": "true",
            "--continuous-log-logGroup": f"/aws-glue/jobs/{prefix}",
            "--TempDir": f"s3://{glue_logs.bucket_name}/temp/",
            "--enable-spark-ui": "true",
            "--spark-event-logs-path": f"s3://{glue_logs.bucket_name}/spark-logs/",
        },
        tags={"Environment": "alpha", "Service": "basalt-data",
              "Stack": "BasaltDataAnalyzer-Glue-alpha"},
    )
    exports(
        s,
        FlintDataBucketName=buckets["FlintDataBucket"].bucket_name,
        GlueAssetsBucketName=assets.bucket_name,
        GlueLogsBucketName=glue_logs.bucket_name,
        GlueJobRoleArn=role.role_arn,
        GlueJobName=job.ref,
        DeploymentRegion=s.region,
        HomeRegion=home_region,
    )


def spark_cluster(s: cdk.Stack, *, prefix: str) -> None:
    """A private EMR 5 cluster whose Spark defaults ask for far more than its two nodes hold."""
    vpc = make_vpc(s, "EmrVpc", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24),
                   vpc_name=f"{prefix}-emr-vpc", max_azs=3, nat_gateways=1)

    def group(logical, name, description):
        return ec2.SecurityGroup(s, logical, vpc=vpc, description=description,
                                 security_group_name=f"{prefix}-{name}")

    primary = group("EmrManagedPrimarySG", "emr-primary-sg",
                    "EMR managed security group for primary nodes")
    core = group("EmrManagedCoreSG", "emr-core-sg", "EMR managed security group for core nodes")
    service = group("ServiceAccessSG", "emr-service-access-sg", "EMR service access security group")
    additional = group("AdditionalSG", "emr-additional-sg",
                       "Additional security group for EMR nodes")

    revoker_role = iam.Role(s, "SecurityGroupRuleRevokerRole",
                            assumed_by=_service("lambda"),
                            managed_policies=[_managed(
                                "service-role/AWSLambdaBasicExecutionRole")])
    revoker_role.add_to_policy(iam.PolicyStatement(actions=["ec2:DescribeSecurityGroups"],
                                                   resources=["*"]))
    revoker_role.add_to_policy(iam.PolicyStatement(
        actions=["ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress"],
        resources=[f"arn:{s.partition}:ec2:{s.region}:{s.account}:security-group/"
                   f"{g.security_group_id}" for g in (primary, core, service, additional)]))
    revoker_logs = logs.LogGroup(s, "SecurityGroupRuleRevokerLogs", removal_policy=DESTROY)
    revoker = lambda_.Function(s, "SecurityGroupRuleRevoker",
                               runtime=lambda_.Runtime.PYTHON_3_12,
                               handler="index.handler",
                               code=lambda_.Code.from_inline(_RULE_REVOKER),
                               timeout=Duration.seconds(120),
                               role=revoker_role,
                               log_group=revoker_logs)
    rule_cleanup = cdk.CustomResource(
        s, "EmrSecurityGroupRuleCleanup", service_token=revoker.function_arn,
        properties={"GroupIds": [g.security_group_id
                                 for g in (primary, core, service, additional)]})
    rule_cleanup.node.add_dependency(revoker_role)

    # The template's own rules are deleted before the cleanup revokes what EMR added.
    rules = [
        ec2.CfnSecurityGroupIngress(s, "PrimaryFromCore", group_id=primary.security_group_id,
                                    ip_protocol="-1",
                                    source_security_group_id=core.security_group_id,
                                    description="Allow all traffic from core nodes"),
        ec2.CfnSecurityGroupIngress(s, "CoreFromPrimary", group_id=core.security_group_id,
                                    ip_protocol="-1",
                                    source_security_group_id=primary.security_group_id,
                                    description="Allow all traffic from primary node"),
        ec2.CfnSecurityGroupIngress(
            s, "ServiceAccessFromPrimary", group_id=service.security_group_id,
            ip_protocol="tcp", from_port=9443, to_port=9443,
            source_security_group_id=primary.security_group_id,
            description="Allow EMR service access from primary node on port 9443"),
    ]
    for rule in rules:
        rule.node.add_dependency(rule_cleanup)

    cse_key = kms.Key(s, "S3EncryptionKey",
                      description="KMS key for EMR S3 client-side encryption (EMRFS)",
                      enable_key_rotation=True, removal_policy=DESTROY)
    logs_bucket = secure_bucket(s, "EmrLogsBucket", bucket_name=f"{prefix}-basalt-logs")
    service_role = iam.Role(
        s, "EmrServiceRole", role_name=f"{prefix}-emr-default",
        assumed_by=_service("elasticmapreduce"),
        managed_policies=[_managed(
            "service-role/AmazonElasticMapReduceRole")])
    ec2_role = iam.Role(
        s, "EmrEc2Role", role_name=f"{prefix}-emr-ec2-processing",
        assumed_by=_service("ec2"),
        managed_policies=[_managed(
            "service-role/AmazonElasticMapReduceforEC2Role")])
    logs_bucket.grant_read_write(ec2_role)
    cse_key.grant_encrypt_decrypt(ec2_role)
    profile = iam.CfnInstanceProfile(s, "EmrEc2InstanceProfile",
                                     instance_profile_name=f"{prefix}-emr-ec2-processing",
                                     roles=[ec2_role.role_name])

    def fleet(name):
        return emr.CfnCluster.InstanceFleetConfigProperty(
            name=name, target_on_demand_capacity=1, target_spot_capacity=0,
            instance_type_configs=[emr.CfnCluster.InstanceTypeConfigProperty(
                instance_type="m5.2xlarge")])

    def classification(name, properties):
        return emr.CfnCluster.ConfigurationProperty(classification=name,
                                                    configuration_properties=properties)

    cluster = emr.CfnCluster(
        s, "EmrSparkCluster",
        name=f"{prefix}-basalt-spark",
        release_label="emr-5.36.1",
        applications=[emr.CfnCluster.ApplicationProperty(name=n)
                      for n in ("Spark", "Zeppelin", "Hadoop", "Pig")],
        service_role=service_role.role_name,
        job_flow_role=profile.ref,
        log_uri=f"s3n://{logs_bucket.bucket_name}/clusters/",
        visible_to_all_users=True,
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            ec2_subnet_id=vpc.private_subnets[0].subnet_id,
            emr_managed_master_security_group=primary.security_group_id,
            emr_managed_slave_security_group=core.security_group_id,
            service_access_security_group=service.security_group_id,
            additional_master_security_groups=[additional.security_group_id],
            additional_slave_security_groups=[additional.security_group_id],
            termination_protected=False,
            unhealthy_node_replacement=True,
            master_instance_fleet=fleet("PrimaryInstanceFleet"),
            core_instance_fleet=fleet("CoreInstanceFleet"),
        ),
        configurations=[
            classification("emrfs-site", {
                "fs.s3.cse.enabled": "true",
                "fs.s3.cse.encryptionMaterialsProvider":
                    "com.amazon.ws.emr.hadoop.fs.cse.KMSEncryptionMaterialsProvider",
                "fs.s3.cse.kms.keyId": cse_key.key_arn,
                "fs.s3.instance.profile.retry.count": "5",
                "fs.s3.instance.profile.retry.period.seconds": "5",
            }),
            classification("spark", {"maximizeResourceAllocation": "false"}),
            classification("spark-defaults", {
                "spark.dynamicAllocation.enabled": "false",
                "spark.sql.adaptive.enabled": "true",
                "spark.executor.memory": "20G",
                "spark.yarn.executor.memoryOverhead": "3G",
                "spark.yarn.maxAppAttempts": "1",
                "spark.shuffle.service.enabled": "false",
                "spark.executor.instances": "425",
                "spark.executor.cores": "4",
                "spark.driver.memory": "60G",
                "spark.driver.maxResultSize": "60G",
                "spark.sql.autoBroadcastJoinThreshold": "-1",
                "spark.driver.cores": "8",
                "spark.sql.shuffle.partitions": "3000",
                "spark.speculation": "false",
            }),
        ],
        scale_down_behavior="TERMINATE_AT_TASK_COMPLETION",
        step_concurrency_level=1,
        tags=[cdk.CfnTag(key="Environment", value="spark-alpha"),
              cdk.CfnTag(key="Service", value="Basalt")],
    )
    cluster.node.add_dependency(profile)
    # The cluster terminates before its rule cleanup runs and before its log bucket empties.
    cluster.node.add_dependency(rule_cleanup)
    for rule in rules:
        cluster.node.add_dependency(rule)
    written_by(logs_bucket, cluster)

    exports(
        s,
        EmrClusterId=cluster.ref,
        LogsBucketName=logs_bucket.bucket_name,
        S3EncryptionKeyArn=cse_key.key_arn,
        EmrServiceRoleArn=service_role.role_arn,
        EmrEc2RoleArn=ec2_role.role_arn,
    )


_SSM_CORE = "AmazonSSMManagedInstanceCore"
_MICRO = ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO)


def _ebs(device: str, size: int, volume_type: ec2.EbsDeviceVolumeType, *,
         delete_on_termination: bool = True, **kwargs) -> ec2.BlockDevice:
    return ec2.BlockDevice(device_name=device, volume=ec2.BlockDeviceVolume.ebs(
        size, volume_type=volume_type, delete_on_termination=delete_on_termination, **kwargs))


def _health_responder(path: str, unit: str) -> ec2.UserData:
    """User data serving 200 on ``path`` at port 4000 under systemd."""
    return ec2.UserData.custom("\n".join([
        "#!/bin/bash",
        "set -euxo pipefail",
        f"cat > /opt/{unit}.py <<'PYEOF'",
        "from http.server import BaseHTTPRequestHandler, HTTPServer",
        "",
        "",
        "class Handler(BaseHTTPRequestHandler):",
        "    def do_GET(self):",
        f"        if self.path == '{path}':",
        "            self.send_response(200)",
        "            self.send_header('Content-Type', 'text/plain')",
        "            self.end_headers()",
        "            self.wfile.write(b'OK')",
        "        else:",
        "            self.send_response(404)",
        "            self.end_headers()",
        "",
        "    def log_message(self, *args):",
        "        pass",
        "",
        "",
        "HTTPServer(('0.0.0.0', 4000), Handler).serve_forever()",
        "PYEOF",
        f"cat > /etc/systemd/system/{unit}.service <<'UNITEOF'",
        "[Unit]",
        f"Description=Health responder for {path} on port 4000",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        f"ExecStart=/usr/bin/python3 /opt/{unit}.py",
        "Restart=always",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "UNITEOF",
        "systemctl daemon-reload",
        f"systemctl enable --now {unit}.service",
    ]))


def legacy_ami_instance(s: cdk.Stack, *, prefix: str) -> None:
    """An Amazon Linux 2 instance, IMDSv2 only, admitting SSH from a prefix list."""
    vpc = make_vpc(s, "VPC", ("Public", PUBLIC, 24), vpc_name=f"{prefix}-appstack-vpc", max_azs=1,
                   nat_gateways=0)
    group = ec2.SecurityGroup(s, "EC2SecurityGroup", vpc=vpc,
                              description="Security group for EC2 instance",
                              security_group_name=f"{prefix}-appstack-ec2-sg")
    group.add_ingress_rule(prefix_list(s, "CorporateRanges", f"{prefix}-corporate"),
                           ec2.Port.tcp(22), "Allow SSH access from the corporate network")
    role = iam.Role(s, "EC2Role", role_name=f"{prefix}-appstack-ec2",
                    assumed_by=_service("ec2"),
                    description="IAM role for EC2 instance with SSM access",
                    managed_policies=[_managed(_SSM_CORE)])
    profile = iam.CfnInstanceProfile(s, "EC2InstanceProfile",
                                     instance_profile_name=f"{prefix}-appstack-ec2",
                                     roles=[role.role_name])
    instance = ec2.Instance(
        s, "EC2Instance", vpc=vpc,
        vpc_subnets=select(PUBLIC),
        associate_public_ip_address=False,
        instance_type=_MICRO,
        machine_image=ec2.MachineImage.latest_amazon_linux2(),
        security_group=group, role=role, require_imdsv2=True,
        block_devices=[_ebs("/dev/xvda", 8, ec2.EbsDeviceVolumeType.GP2, encrypted=False)],
    )
    instance.node.add_dependency(profile)
    cdk.Tags.of(instance).add("Name", "AppStack-dev/App-EC2-dev")

    exports(
        s,
        VPCId=vpc.vpc_id,
        EC2InstanceId=instance.instance_id,
        EC2InstancePrivateIp=instance.instance_private_ip,
        EC2SecurityGroupId=group.security_group_id,
        EC2RoleName=role.role_name,
        EC2InstanceProfileName=profile.instance_profile_name,
        EC2AmiId=instance.node.default_child.image_id,
    )


def private_nat_server(s: cdk.Stack, *, prefix: str, zone: str) -> None:
    """An app server in a private subnet routed through a NAT gateway, with a kept data volume."""
    vpc = ec2.Vpc(s, "FlintProdVpc", ip_addresses=ec2.IpAddresses.cidr("172.31.0.0/16"),
                  max_azs=1, nat_gateways=0, subnet_configuration=[],
                  enable_dns_hostnames=True, enable_dns_support=True)
    cdk.Tags.of(vpc).add("Managed resource", "Garnet")
    igw = ec2.CfnInternetGateway(s, "InternetGateway")
    attachment = ec2.CfnVPCGatewayAttachment(s, "VPCGatewayAttachment", vpc_id=vpc.vpc_id,
                                             internet_gateway_id=igw.ref)
    public = ec2.PublicSubnet(s, "PublicSubnet", vpc_id=vpc.vpc_id,
                              cidr_block="172.31.16.0/20", availability_zone=zone,
                              map_public_ip_on_launch=False)
    ec2.CfnRoute(s, "PublicSubnetDefaultRoute",
                 route_table_id=public.route_table.route_table_id,
                 destination_cidr_block="0.0.0.0/0",
                 gateway_id=igw.ref).node.add_dependency(attachment)
    # A bare subnet, so its one route table association is the named table's below.
    private_cfn = ec2.CfnSubnet(s, "FlintProdSubnetPrivateAppDb", vpc_id=vpc.vpc_id,
                                cidr_block="172.31.0.0/20", availability_zone=zone,
                                map_public_ip_on_launch=False,
                                tags=[cdk.CfnTag(key="Name",
                                                 value="Flint-prod-subnet-private-app-db")])
    eip = ec2.CfnEIP(s, "NatGatewayEIP", domain="vpc")
    nat = ec2.CfnNatGateway(s, "FlintProdNatGateway", subnet_id=public.subnet_id,
                            allocation_id=eip.attr_allocation_id, connectivity_type="public")
    nat.node.add_dependency(attachment)
    route_table = ec2.CfnRouteTable(
        s, "FlintProdPrivateSubnetRouteTable", vpc_id=vpc.vpc_id,
        tags=[cdk.CfnTag(key="Name", value="Flint-prod-private-subnet-route-table")])
    ec2.CfnRoute(s, "RouteToNatGateway", route_table_id=route_table.ref,
                 destination_cidr_block="0.0.0.0/0", nat_gateway_id=nat.ref)
    ec2.CfnSubnetRouteTableAssociation(s, "PrivateSubnetRouteTableAssociation",
                                       subnet_id=private_cfn.ref,
                                       route_table_id=route_table.ref)
    private = ec2.Subnet.from_subnet_attributes(s, "PrivateAppDb",
                                                subnet_id=private_cfn.ref,
                                                availability_zone=zone,
                                                route_table_id=route_table.ref)

    app_sg = ec2.SecurityGroup(s, "FlintProdSgAppServer", vpc=vpc,
                               description="App server security group")
    cdk.Tags.of(app_sg).add("Name", "Flint-prod-sg-app-alb")
    app_sg.add_ingress_rule(ec2.Peer.ipv4("172.31.0.0/20"), ec2.Port.tcp(8080),
                            "Allow 8080 from subnet")
    app_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.2.32/32"), ec2.Port.tcp(22),
                            "Private connection to prod server")
    app_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.3.2/32"), ec2.Port.tcp(22),
                            "Private connection to prod server")
    app_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.3.2/32"), ec2.Port.all_icmp(),
                            "Ping from prod server")
    alb_sg_name = f"{prefix}-flint-prod-alb-sg"
    alb_sg = ec2.SecurityGroup(s, "FlintProdAlbSg", vpc=vpc,
                               security_group_name=alb_sg_name,
                               description="ALB security group")
    cdk.Tags.of(alb_sg).add("Name", "Flint-prod-ALB-SG")
    app_sg.add_ingress_rule(alb_sg, ec2.Port.tcp(8081))
    ssh_sg = ec2.SecurityGroup(s, "FlintAllowProdCorpSsh", vpc=vpc, description="Open ssh to corp")
    cdk.Tags.of(ssh_sg).add("Name", "Flint-prod-sg-app-ssh")
    ssh_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/20"), ec2.Port.tcp(22), "SSH from corp network")
    ssh_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.16.0/23"), ec2.Port.tcp(22),
                            "SSH from corp network")
    ssh_sg.add_ingress_rule(prefix_list(s, "CorporateRanges", f"{prefix}-flint-corp"),
                            ec2.Port.tcp(22), "SSH from prefix list")

    role = iam.Role(s, "FlintOnyxAppServerRole",
                    assumed_by=_service("ec2"),
                    role_name=f"{prefix}-flint-onyx-app", path="/")
    profile = iam.CfnInstanceProfile(s, "FlintOnyxInstanceProfile", roles=[role.role_name],
                                     instance_profile_name=f"{prefix}-flint-onyx-app",
                                     path="/")
    instance = ec2.Instance(
        s, "FlintOnyxAppServer", vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnets=[private]),
        instance_type=_MICRO,
        machine_image=ec2.MachineImage.latest_amazon_linux2023(),
        security_group=app_sg, role=role,
        block_devices=[
            _ebs("/dev/xvda", 100, ec2.EbsDeviceVolumeType.GP3),
            # Kept when the instance terminates.
            _ebs("/dev/sdf", 100, ec2.EbsDeviceVolumeType.GP3, delete_on_termination=False),
        ],
        detailed_monitoring=True, require_imdsv2=True,
    )
    instance.add_security_group(ssh_sg)
    instance.node.add_dependency(profile)
    for key, value in (("Service", "Flint-PLM"), ("AutoPatch", "enabled"),
                       ("Environment", "prod"), ("Name", "Flint-prod-Garnet - Onyx12.1")):
        cdk.Tags.of(instance).add(key, value)

    exports(
        s,
        VpcId=vpc.vpc_id,
        PrivateSubnetId=private_cfn.ref,
        InstanceId=instance.instance_id,
        InstancePrivateIp=instance.instance_private_ip,
        AppServerSecurityGroupId=app_sg.security_group_id,
        AlbSecurityGroupId=alb_sg.security_group_id,
        AlbSecurityGroupName=alb_sg_name,
        SshSecurityGroupId=ssh_sg.security_group_id,
        NatGatewayId=nat.ref,
        RouteTableId=route_table.ref,
    )


def transit_firewall(s: cdk.Stack, *, prefix: str) -> None:
    """Three VPCs on a transit gateway with static routes, and two firewalls in the DMZ VPC."""
    isolated = select(ISOLATED)

    def vpc(logical, cidr, subnet_name):
        return make_vpc(s, logical, (subnet_name, ISOLATED, 24), cidr=cidr, max_azs=2,
                        nat_gateways=0, enable_dns_hostnames=True, enable_dns_support=True)

    workload = vpc("WorkloadVPC", "10.1.0.0/16", "workload-subnet")
    dmz = vpc("DMZVPC", "10.2.0.0/16", "dmz-subnet")
    cdk.Tags.of(dmz).add("Name", "DMZVPC")
    additional = vpc("AdditionalVPC1", "10.3.0.0/16", "additional-subnet")

    tgw = ec2.CfnTransitGateway(
        s, "MainTransitGateway", amazon_side_asn=64512,
        default_route_table_association="disable", default_route_table_propagation="disable",
        dns_support="enable", vpn_ecmp_support="enable",
        tags=[cdk.CfnTag(key="Name", value="main-transit-gateway")])
    tgw_rt = ec2.CfnTransitGatewayRouteTable(
        s, "MainTGWRouteTable", transit_gateway_id=tgw.attr_id,
        tags=[cdk.CfnTag(key="Name", value="main-tgw-route-table")])
    attachments = {}
    for key, logical, network, tag in (
            ("workload", "WorkloadVPCAttachment", workload, "workload-vpc-attachment"),
            ("dmz", "DMZVPCAttachment", dmz, "dmz-vpc-attachment"),
            ("additional", "AdditionalVPC1Attachment", additional,
             "additional-vpc-1-attachment")):
        attachments[key] = ec2.CfnTransitGatewayAttachment(
            s, logical, transit_gateway_id=tgw.attr_id, vpc_id=network.vpc_id,
            subnet_ids=[subnet.subnet_id for subnet in network.isolated_subnets],
            tags=[cdk.CfnTag(key="Name", value=tag)])
    for key, logical in (("workload", "WorkloadAttachmentAssociation"),
                         ("dmz", "DMZAttachmentAssociation"),
                         ("additional", "AdditionalAttachment1Association")):
        ec2.CfnTransitGatewayRouteTableAssociation(
            s, logical, transit_gateway_attachment_id=attachments[key].attr_id,
            transit_gateway_route_table_id=tgw_rt.ref)
    for logical, cidr, key in (("TGWRouteDefault", "0.0.0.0/0", "dmz"),
                               ("TGWRouteWorkload", "10.1.0.0/16", "workload"),
                               ("TGWRouteDMZ", "10.2.0.0/16", "dmz"),
                               ("TGWRouteAdditional1", "10.3.0.0/16", "additional")):
        ec2.CfnTransitGatewayRoute(s, logical, transit_gateway_route_table_id=tgw_rt.ref,
                                   destination_cidr_block=cidr,
                                   transit_gateway_attachment_id=attachments[key].attr_id)
    for index, subnet in enumerate(workload.isolated_subnets):
        ec2.CfnRoute(s, f"WorkloadTGWRoute{index}",
                     route_table_id=subnet.route_table.route_table_id,
                     destination_cidr_block="0.0.0.0/0",
                     transit_gateway_id=tgw.attr_id).node.add_dependency(attachments["workload"])

    role = iam.Role(s, "WorkloadInstanceRole",
                    assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])
    instance = ec2.Instance(s, "WorkloadInstance", vpc=workload, vpc_subnets=isolated,
                            instance_type=_MICRO,
                            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
                            role=role, ssm_session_permissions=True,
                            require_imdsv2=True)

    firewalls = {}
    for key, name in (("Outbound", "FWOUT"), ("Inbound", "FWIN")):
        policy = networkfirewall.CfnFirewallPolicy(
            s, f"{key}FirewallPolicy",
            firewall_policy_name=f"{prefix}-{name}-policy-DMZVPC",
            firewall_policy=networkfirewall.CfnFirewallPolicy.FirewallPolicyProperty(
                stateless_default_actions=["aws:forward_to_sfe"],
                stateless_fragment_default_actions=["aws:forward_to_sfe"]))
        firewalls[key] = networkfirewall.CfnFirewall(
            s, f"{key}Firewall", firewall_name=f"{prefix}-{name}-DMZVPC",
            firewall_policy_arn=policy.attr_firewall_policy_arn, vpc_id=dmz.vpc_id,
            subnet_mappings=[
                networkfirewall.CfnFirewall.SubnetMappingProperty(subnet_id=subnet.subnet_id)
                for subnet in dmz.isolated_subnets])

    exports(
        s,
        WorkloadVPCId=workload.vpc_id,
        DMZVPCId=dmz.vpc_id,
        AdditionalVPC1Id=additional.vpc_id,
        TransitGatewayId=tgw.attr_id,
        WorkloadInstanceId=instance.instance_id,
        OutboundFirewallArn=firewalls["Outbound"].attr_firewall_arn,
        InboundFirewallArn=firewalls["Inbound"].attr_firewall_arn,
        WorkloadSubnetId=workload.isolated_subnets[0].subnet_id,
        WorkloadSubnetRouteTableId=workload.isolated_subnets[0].route_table.route_table_id,
        TGWRouteTableId=tgw_rt.ref,
        WorkloadVPCAttachmentId=attachments["workload"].attr_id,
        DMZVPCAttachmentId=attachments["dmz"].attr_id,
        AdditionalVPC1AttachmentId=attachments["additional"].attr_id,
        DMZSubnetAId=dmz.isolated_subnets[0].subnet_id,
        DMZSubnetBId=dmz.isolated_subnets[1].subnet_id,
    )


def helper_asg(s: cdk.Stack, *, prefix: str) -> None:
    """An empty Auto Scaling group of helper instances, tagged with a foreign subnet and group."""
    vpc = make_vpc(s, "MainVPC", ("HelperPrimary", PUBLIC, 24), ("Customer", PUBLIC, 24),
                   vpc_name=f"{prefix}-main-vpc", max_azs=2, nat_gateways=0)
    vpc.add_gateway_endpoint("S3Endpoint", service=ec2.GatewayVpcEndpointAwsService.S3)
    helper_subnet, customer_subnet = vpc.public_subnets[0], vpc.public_subnets[2]
    helper_sg = ec2.SecurityGroup(s, "HelperSecurityGroup", vpc=vpc,
                                  security_group_name=f"{prefix}-helper-sg",
                                  description="Security group for Helper instances")
    customer_sg = ec2.SecurityGroup(s, "CustomerSecurityGroup", vpc=vpc,
                                    security_group_name=f"{prefix}-customer-sg",
                                    description="Security group for customer resources")
    cdk.Tags.of(customer_sg).add("Purpose", "Customer-Secondary-ENI-Security")
    cdk.Tags.of(customer_subnet).add("Purpose", "Customer-Secondary-ENI-Attachment")
    role = iam.Role(s, "HelperInstanceRole", role_name=f"{prefix}-helper-instance",
                    assumed_by=_service("ec2"))
    role.add_to_policy(iam.PolicyStatement(
        actions=["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"],
        resources=["*"]))
    template = ec2.LaunchTemplate(
        s, "HelperLT", launch_template_name=f"{prefix}-helper-lt",
        instance_type=_MICRO, machine_image=ec2.MachineImage.latest_amazon_linux2023(),
        security_group=helper_sg, role=role, require_imdsv2=True,
        block_devices=[_ebs("/dev/xvda", 100, ec2.EbsDeviceVolumeType.GP3)])
    group = autoscaling.AutoScalingGroup(
        s, "HelperASG", auto_scaling_group_name=f"{prefix}-helper-asg", vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnets=[helper_subnet]), launch_template=template,
        min_capacity=0, max_capacity=1, desired_capacity=0)
    tags = {
        "ClusterArn": f"arn:{s.partition}:sagemaker:{s.region}:{s.account}:cluster/"
                      "app-cluster",
        "InstanceGroupName": "group1",
        "AppVersion": "2",
        # Literal ids of another network, not references to this stack's.
        "Customer-SG": "sg-01eeee4696a5c0ace",
        "Customer-Subnet": "subnet-0ff0f7602567267d1",
    }
    for key, value in tags.items():
        cdk.Tags.of(group).add(key, value)

    exports(
        s,
        VPCId=vpc.vpc_id,
        HelperSubnetId=helper_subnet.subnet_id,
        CustomerSubnetId=customer_subnet.subnet_id,
        HelperSecurityGroupId=helper_sg.security_group_id,
        CustomerSecurityGroupId=customer_sg.security_group_id,
        InstanceRoleName=role.role_name,
        LaunchTemplateId=template.launch_template_id,
        AutoScalingGroupName=group.auto_scaling_group_name,
        CustomerSGTagValue=tags["Customer-SG"],
        CustomerSubnetTagValue=tags["Customer-Subnet"],
    )


def dual_vpc_helper(s: cdk.Stack, *, prefix: str) -> None:
    """A helper instance spanning two VPCs whose role may read a secret but not decrypt its key."""
    helper_vpc = make_vpc(s, "HelperVPC", ("HelperPrimary", PUBLIC, 23),
                          vpc_name=f"{prefix}-helper-vpc", cidr="172.25.0.0/16", max_azs=2,
                          nat_gateways=0)
    customer_vpc = make_vpc(s, "CustomerVPC", ("CustomerSecondary", PUBLIC, 16),
                            vpc_name=f"{prefix}-customer-vpc", cidr="10.1.0.0/16", max_azs=1,
                            nat_gateways=0)
    helper_subnet = helper_vpc.public_subnets[0]
    customer_subnet = customer_vpc.public_subnets[0]
    helper_sg = ec2.SecurityGroup(
        s, "HelperSecurityGroup", vpc=helper_vpc,
        security_group_name=f"{prefix}-helper-primary-sg",
        description="Security group for Helper instance primary interface")
    customer_sg = ec2.SecurityGroup(
        s, "CustomerSecurityGroup", vpc=customer_vpc,
        security_group_name=f"{prefix}-no-ingress-sg",
        description="Security group with no ingress rules for customer network")
    key = kms.Key(s, "AppProxyKey", description="App Proxy Certificate Encryption Key",
                  enable_key_rotation=True, removal_policy=DESTROY)
    # The role may call Secrets Manager but holds no kms:Decrypt for the secret's key.
    role = iam.Role(s, "HelperInstanceRole", role_name=f"{prefix}-helper-dual-vpc",
                    assumed_by=_service("ec2"),
                    description="IAM role for Helper instance")
    role.add_to_policy(iam.PolicyStatement(
        actions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
        resources=["*"]))
    profile = iam.CfnInstanceProfile(s, "HelperInstanceProfile",
                                     instance_profile_name=f"{prefix}-helper-dual-vpc",
                                     roles=[role.role_name])
    secret = secretsmanager.Secret(
        s, "AppProxyCertificate", secret_name=f"{prefix}-app-certificate",
        description="App Proxy Server Certificate and private key", encryption_key=key,
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({
                "certificate": "placeholder-certificate-data",
                "privateKey": "placeholder-private-key-data"}),
            generate_string_key="password"))
    instance = ec2.Instance(
        s, "HelperInstance", instance_type=_MICRO,
        machine_image=ec2.MachineImage.latest_amazon_linux2023(
            cpu_type=ec2.AmazonLinuxCpuType.X86_64),
        vpc=helper_vpc, vpc_subnets=ec2.SubnetSelection(subnets=[helper_subnet]),
        associate_public_ip_address=False,
        security_group=helper_sg, role=role, require_imdsv2=True,
        block_devices=[_ebs("/dev/xvda", 30, ec2.EbsDeviceVolumeType.GP3)])
    for k, v in (("ClusterArn", f"arn:{s.partition}:sagemaker:{s.region}:"
                                f"{s.account}:cluster/app-cluster"),
                 ("InstanceGroupName", "group1"), ("AppVersion", "2"), ("sagemaker", "true")):
        cdk.Tags.of(instance).add(k, v)
    eni = ec2.CfnNetworkInterface(s, "SecondaryNetworkInterface",
                                  subnet_id=customer_subnet.subnet_id,
                                  group_set=[customer_sg.security_group_id],
                                  description="Secondary network interface in customer VPC")
    ec2.CfnNetworkInterfaceAttachment(s, "SecondaryNetworkInterfaceAttachment",
                                      instance_id=instance.instance_id,
                                      network_interface_id=eni.ref, device_index="1",
                                      delete_on_termination=False)

    exports(
        s,
        HelperVpcId=helper_vpc.vpc_id,
        CustomerVpcId=customer_vpc.vpc_id,
        InstanceId=instance.instance_id,
        InstanceRoleArn=role.role_arn,
        InstanceProfileArn=profile.attr_arn,
        SecondaryNetworkInterfaceId=eni.ref,
        SecretArn=secret.secret_arn,
        KmsKeyId=key.key_id,
        KmsKeyArn=key.key_arn,
    )


def disabled_key_asg(s: cdk.Stack, *, prefix: str) -> None:
    """An Auto Scaling group whose launch template encrypts its root volume with a disabled key."""
    vpc = make_vpc(s, "CustomerVpc", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24),
                   vpc_name=f"{prefix}-app-service-vpc", max_azs=2, nat_gateways=1)
    customer_subnet = vpc.private_subnets[0]
    platform_sg = ec2.SecurityGroup(
        s, "PlatformSecurityGroup", vpc=vpc, security_group_name=f"{prefix}-platform-sg",
        description="Platform-managed security group for helper instances")
    customer_sg = ec2.SecurityGroup(
        s, "CustomerSecurityGroup", vpc=vpc, security_group_name=f"{prefix}-customer-sg",
        description="Customer-provided security group")
    cdk.Tags.of(customer_sg).add("Type", "Customer-SG")
    role = iam.Role(s, "HelperInstanceRole", role_name=f"{prefix}-helper-disabled-key",
                    description="IAM role for helper EC2 instances",
                    assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])
    key = kms.Key(s, "CrossAccountAmiEncryptionKey",
                  description="cross-account AMI encryption key (disabled)",
                  enabled=False, enable_key_rotation=False,
                  removal_policy=DESTROY)
    bucket = secure_bucket(s, "CustomerEscrowBucket", bucket_name=f"{prefix}-app-escrow")
    role.add_to_policy(iam.PolicyStatement(
        actions=["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        resources=[bucket.bucket_arn, f"{bucket.bucket_arn}/*"]))
    template_name = f"{prefix}-helper-lt-disabled-key"
    template = ec2.LaunchTemplate(
        s, "HelperLaunchTemplate", launch_template_name=template_name,
        instance_type=_MICRO,
        machine_image=ec2.MachineImage.latest_amazon_linux2023(
            cpu_type=ec2.AmazonLinuxCpuType.X86_64),
        role=role, security_group=platform_sg, require_imdsv2=True,
        block_devices=[_ebs("/dev/xvda", 100, ec2.EbsDeviceVolumeType.GP2, encrypted=True,
                            kms_key=key)],
        user_data=ec2.UserData.for_linux())
    cfn_template = template.node.default_child
    cfn_template.add_property_override("LaunchTemplateData.SecurityGroupIds", [
        platform_sg.security_group_id, customer_sg.security_group_id])
    cfn_template.add_property_override("LaunchTemplateData.TagSpecifications", [{
        "ResourceType": "instance",
        "Tags": [
            {"Key": "AppVersion", "Value": "2"},
            {"Key": "ClusterArn", "Value": f"arn:{s.partition}:sagemaker:{s.region}:"
                                           f"{s.account}:cluster/app-cluster-disabled-key"},
            {"Key": "InstanceGroupName", "Value": "group1"},
            {"Key": "Customer-Subnet", "Value": customer_subnet.subnet_id},
            {"Key": "Customer-SG", "Value": customer_sg.security_group_id},
            {"Key": "EnvironmentId", "Value": "disabled-key"},
        ],
    }])
    group = autoscaling.AutoScalingGroup(
        s, "HelperAsg", auto_scaling_group_name=f"{prefix}-helper-asg-disabled-key",
        vpc=vpc, vpc_subnets=ec2.SubnetSelection(subnets=[customer_subnet]),
        launch_template=template, min_capacity=0, max_capacity=1, desired_capacity=0)

    exports(
        s,
        VpcId=vpc.vpc_id,
        CustomerSubnetId=customer_subnet.subnet_id,
        PlatformSecurityGroupId=platform_sg.security_group_id,
        CustomerSecurityGroupId=customer_sg.security_group_id,
        InstanceRoleArn=role.role_arn,
        InstanceRoleName=role.role_name,
        KmsKeyId=key.key_id,
        KmsKeyArn=key.key_arn,
        KmsKeyState="DISABLED",
        LaunchTemplateId=template.launch_template_id,
        LaunchTemplateName=template_name,
        AutoScalingGroupName=group.auto_scaling_group_name,
        EscrowBucketName=bucket.bucket_name,
        AccountRootArn=f"arn:{s.partition}:iam::{s.account}:root",
    )


def private_load_balancers(s: cdk.Stack, *, prefix: str) -> None:
    """A jump server without a public address and an internal ALB and NLB."""
    vpc = make_vpc(s, "StagingVpc", ("public", PUBLIC, 24), ("private", ISOLATED, 24),
                   vpc_name=f"{prefix}-garnet-staging-vpc", cidr="10.0.0.0/16", max_azs=2,
                   nat_gateways=0)
    public_subnet = vpc.public_subnets[0]
    db_sg = ec2.SecurityGroup(s, "DatabaseSg", vpc=vpc,
                              security_group_name=f"{prefix}-db-sg",
                              description="Database security group")
    jump_sg = ec2.SecurityGroup(s, "JumpServerSg", vpc=vpc,
                                security_group_name=f"{prefix}-db-jump-server-sg-01",
                                description="Security group for the database jump server",
                                allow_all_outbound=False)
    jump_sg.add_ingress_rule(prefix_list(s, "RegionalRanges", f"{prefix}-regional"),
                             ec2.Port.tcp(22), "Regional ranges")
    jump_sg.add_ingress_rule(prefix_list(s, "ProdRanges", f"{prefix}-prod",
                                         ("10.0.32.0/20",)),
                             ec2.Port.tcp(22), "Prod ranges")
    jump_sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(3306), "MySQL to anywhere")
    jump_sg.add_egress_rule(ec2.Peer.security_group_id(db_sg.security_group_id),
                            ec2.Port.tcp(3306), "Database SG")
    jump_sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS to anywhere")
    role = iam.Role(s, "JumpServerRole", role_name=f"{prefix}-jump-server",
                    assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])
    jump = ec2.Instance(
        s, "JumpServer", instance_name=f"{prefix}-db-jump-server", vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnets=[public_subnet]),
        instance_type=_MICRO, machine_image=ec2.MachineImage.latest_amazon_linux2023(),
        security_group=jump_sg, role=role, associate_public_ip_address=False,
        block_devices=[_ebs("/dev/xvda", 8, ec2.EbsDeviceVolumeType.GP3)])
    jump.node.default_child.add_property_override("MetadataOptions", {
        "HttpTokens": "required", "HttpPutResponseHopLimit": 1, "HttpEndpoint": "enabled"})
    private = ec2.SubnetSelection(subnets=vpc.isolated_subnets[:2])
    alb_sg = ec2.SecurityGroup(s, "AlbSg", vpc=vpc,
                               security_group_name=f"{prefix}-garnet-backend-alb-sg",
                               description="Security group for the backend ALB")
    alb = elbv2.ApplicationLoadBalancer(
        s, "BackendAlb", load_balancer_name=f"{prefix}-alb02", vpc=vpc,
        vpc_subnets=private, internet_facing=False, security_group=alb_sg,
        ip_address_type=elbv2.IpAddressType.IPV4)
    nlb = elbv2.NetworkLoadBalancer(
        s, "BackendNlb", load_balancer_name=f"{prefix}-nlb01", vpc=vpc,
        vpc_subnets=private, internet_facing=False, ip_address_type=elbv2.IpAddressType.IPV4)
    cdk.Tags.of(vpc).add("Name", "garnet-staging-vpc")
    cdk.Tags.of(public_subnet).add("Name", "garnet-staging-vpc-public-subnet-01")
    cdk.Tags.of(public_subnet).add("env", "staging")
    cdk.Tags.of(jump).add("Name", "db-jump-server")
    cdk.Tags.of(jump_sg).add("Name", "garnet-db-jump-server-sg")

    exports(
        s,
        VpcId=vpc.vpc_id,
        PublicSubnetId=public_subnet.subnet_id,
        JumpServerInstanceId=jump.instance_id,
        JumpServerPrivateIp=jump.instance_private_ip,
        AlbArn=alb.load_balancer_arn,
        AlbDnsName=alb.load_balancer_dns_name,
        NlbArn=nlb.load_balancer_arn,
        NlbDnsName=nlb.load_balancer_dns_name,
    )


def metadata_tags(s: cdk.Stack, *, prefix: str) -> None:
    """Three IMDSv2 instances; only one exposes its tags through instance metadata."""
    vpc = make_vpc(s, "FlintVpc", ("Private", ISOLATED, 19), vpc_name=f"{prefix}-flint-vpc",
                   cidr="10.0.0.0/16", max_azs=1, nat_gateways=0)
    group = ec2.SecurityGroup(s, "InstanceSg", vpc=vpc, allow_all_outbound=False)
    role = iam.Role(s, "InstanceRole", assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])

    def instance(logical, name, metadata=None):
        created = ec2.Instance(
            s, logical, vpc=vpc,
            vpc_subnets=select(ISOLATED),
            instance_type=_MICRO, machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            security_group=group, role=role, instance_name=f"{prefix}-{name}",
            require_imdsv2=True)
        if metadata:
            created.node.default_child.add_property_override("MetadataOptions", metadata)
        cdk.Tags.of(created).add("Name", name)
        return created

    target = instance("TestDbConnection", "flint-dbserver", {
        "HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 2,
        "HttpProtocolIpv6": "disabled", "InstanceMetadataTags": "enabled"})
    sibling1 = instance("AppServer1", "app-server-1")
    sibling2 = instance("AppServer2", "app-server-2", {
        "HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 3,
        "InstanceMetadataTags": "disabled"})

    exports(
        s,
        InstanceId=target.instance_id,
        OtherInstance1Id=sibling1.instance_id,
        OtherInstance2Id=sibling2.instance_id,
    )


def cluster_nlb(s: cdk.Stack, *, prefix: str, s3_prefix_list: str) -> None:
    """An internal NLB whose health check port the instances' security group never admits."""
    vpc = make_vpc(s, "VPC", ("Private", ISOLATED, 23), vpc_name=f"{prefix}-appcluster-vpc",
                   cidr="172.25.0.0/16", max_azs=2, nat_gateways=0)
    subnet = vpc.isolated_subnets[0]
    group = ec2.SecurityGroup(s, "SecurityGroup", vpc=vpc,
                              security_group_name=f"{prefix}-appcluster-sg",
                              description="Security group for cluster instances",
                              allow_all_outbound=False)
    gid = group.security_group_id
    for logical, protocol, ports, description in (
            ("TCP988", "tcp", (988, 988), "TCP 988"),
            ("AllTraffic", "-1", None, "all traffic"),
            ("TCP1018to1023", "tcp", (1018, 1023), "TCP 1018-1023")):
        span = {"from_port": ports[0], "to_port": ports[1]} if ports else {}
        ec2.CfnSecurityGroupIngress(s, f"Ingress{logical}", group_id=gid,
                                    ip_protocol=protocol, source_security_group_id=gid,
                                    description=f"Allow {description} from self", **span)
        ec2.CfnSecurityGroupEgress(s, f"Egress{logical}", group_id=gid,
                                   ip_protocol=protocol, destination_security_group_id=gid,
                                   description=f"Allow {description} to self", **span)
    ec2.CfnSecurityGroupEgress(s, "EgressPrefixList", group_id=gid, ip_protocol="-1",
                               destination_prefix_list_id=s3_prefix_list,
                               description="Allow all traffic to S3 prefix list")
    cluster_arn = (f"arn:{s.partition}:sagemaker:{s.region}:{s.account}:cluster/" "appcluster")
    cdk.Tags.of(group).add("ClusterArn", cluster_arn)
    role = iam.Role(s, "InstanceRole", role_name=f"{prefix}-appcluster-instance",
                    assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])
    profile = iam.CfnInstanceProfile(s, "InstanceProfile",
                                     instance_profile_name=f"{prefix}-appcluster-instance",
                                     roles=[role.role_name])
    template = ec2.LaunchTemplate(
        s, "LaunchTemplate", launch_template_name=f"{prefix}-appcluster-lt",
        instance_type=_MICRO,
        machine_image=ec2.MachineImage.latest_amazon_linux2023(
            cpu_type=ec2.AmazonLinuxCpuType.X86_64),
        security_group=group, require_imdsv2=True,
        user_data=_health_responder("/health-check", "health-check"))
    cfn_template = template.node.default_child
    cfn_template.add_property_override("LaunchTemplateData.IamInstanceProfile",
                                       {"Name": profile.instance_profile_name})
    cfn_template.add_property_override("LaunchTemplateData.MetadataOptions", {
        "HttpTokens": "required", "HttpPutResponseHopLimit": 2, "HttpEndpoint": "enabled"})
    template.node.add_dependency(profile)
    for k, v in (("AppVersion", "2"), ("ClusterArn", cluster_arn),
                 ("InstanceGroupName", "group1")):
        cdk.Tags.of(template).add(k, v)
    target_group = elbv2.NetworkTargetGroup(
        s, "TargetGroup", target_group_name=f"{prefix}-tgac", vpc=vpc, port=44300,
        protocol=elbv2.Protocol.TCP, target_type=elbv2.TargetType.INSTANCE,
        health_check=elbv2.HealthCheck(
            enabled=True, protocol=elbv2.Protocol.HTTP, port="4000", path="/health-check",
            interval=Duration.seconds(20), timeout=Duration.seconds(10),
            healthy_threshold_count=2, unhealthy_threshold_count=10),
        deregistration_delay=Duration.seconds(300))
    nlb = elbv2.NetworkLoadBalancer(s, "NLB", load_balancer_name=f"{prefix}-nlbac",
                                    vpc=vpc, internet_facing=False,
                                    vpc_subnets=ec2.SubnetSelection(subnets=[subnet]))
    nlb.add_listener("Listener", port=44300, protocol=elbv2.Protocol.TCP,
                     default_target_groups=[target_group])
    group_asg = autoscaling.AutoScalingGroup(
        s, "ASG", auto_scaling_group_name=f"{prefix}-appcluster-group1-asg", vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnets=[subnet]), launch_template=template,
        min_capacity=0, max_capacity=2, desired_capacity=0,
        health_check=autoscaling.HealthCheck.elb(grace=Duration.seconds(200)))
    group_asg.attach_to_network_target_group(target_group)

    exports(
        s,
        VPCId=vpc.vpc_id,
        SubnetId=subnet.subnet_id,
        SecurityGroupId=gid,
        TargetGroupArn=target_group.target_group_arn,
        TargetGroupName=target_group.target_group_name,
        NLBArn=nlb.load_balancer_arn,
        ASGName=group_asg.auto_scaling_group_name,
        LaunchTemplateId=template.launch_template_id,
        InstanceProfileName=profile.instance_profile_name,
    )


def hyper_pod_nlb(s: cdk.Stack, *, prefix: str) -> None:
    """A helper Auto Scaling group behind an internal NLB checking a port nothing admits."""
    helper_vpc = make_vpc(s, "HelperVpc", ("HelperSubnet", PUBLIC, 23), cidr="172.25.0.0/16",
                          max_azs=1, nat_gateways=0)
    workload_vpc = make_vpc(s, "WorkloadVpc", ("WorkloadSubnet", PUBLIC, 20), cidr="10.0.0.0/16",
                            max_azs=1, nat_gateways=0)
    helper_subnet = helper_vpc.public_subnets[0]
    workload_subnet = workload_vpc.public_subnets[0]
    helper_sg = ec2.SecurityGroup(s, "HelperSecurityGroup", vpc=helper_vpc,
                                  description="Quartz-Helper-SG for HyperPod helper instances")
    workload_sg = ec2.SecurityGroup(s, "WorkloadSecurityGroup", vpc=workload_vpc,
                                    description="no-ingress-workload-sg")
    role = iam.Role(s, "QuartzInstanceRole",
                    assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])
    profile = iam.CfnInstanceProfile(s, "QuartzInstanceProfile", roles=[role.role_name],
                                     instance_profile_name=f"{prefix}-quartz-hyperpod")
    nlb = elbv2.NetworkLoadBalancer(s, "HyperPodNLB", vpc=helper_vpc,
                                    internet_facing=False,
                                    load_balancer_name=f"{prefix}-nlbhp")
    target_group = elbv2.NetworkTargetGroup(
        s, "HyperPodTargetGroup", vpc=helper_vpc, port=44300, protocol=elbv2.Protocol.TCP,
        target_type=elbv2.TargetType.INSTANCE, target_group_name=f"{prefix}-tghp",
        health_check=elbv2.HealthCheck(
            enabled=True, protocol=elbv2.Protocol.HTTP, port="4000",
            path="/sync-health-check", interval=Duration.seconds(20),
            timeout=Duration.seconds(10), healthy_threshold_count=2,
            unhealthy_threshold_count=10))
    nlb.add_listener("NLBListener", port=44300, protocol=elbv2.Protocol.TCP,
                     default_target_groups=[target_group])
    template = ec2.LaunchTemplate(
        s, "HyperPodLaunchTemplate", launch_template_name=f"{prefix}-quartz-helper-lt",
        instance_type=_MICRO, machine_image=ec2.MachineImage.latest_amazon_linux2023(),
        security_group=helper_sg, role=role, require_imdsv2=True,
        user_data=_health_responder("/sync-health-check", "sync-health-check"))
    cluster_arn = (f"arn:{s.partition}:sagemaker:{s.region}:{s.account}:cluster/" "cluster1")
    for k, v in (("Quartz-Version", "2"), ("ClusterArn", cluster_arn),
                 ("InstanceGroupName", "group1"),
                 ("Workload-Subnet", workload_subnet.subnet_id),
                 ("Workload-SG", workload_sg.security_group_id), ("IsHelper", "true")):
        cdk.Tags.of(template).add(k, v)
    group = autoscaling.AutoScalingGroup(
        s, "HyperPodHelperASG", vpc=helper_vpc,
        vpc_subnets=ec2.SubnetSelection(subnets=[helper_subnet]), launch_template=template,
        min_capacity=0, max_capacity=2, desired_capacity=0,
        health_check=autoscaling.HealthCheck.elb(grace=Duration.seconds(0)),
        auto_scaling_group_name=f"{prefix}-quartz-helper-asg")
    group.attach_to_network_target_group(target_group)
    for k, v in (("ClusterArn", cluster_arn), ("InstanceGroupName", "group1"),
                 ("Quartz-Version", "2")):
        cdk.Tags.of(group).add(k, v)

    exports(
        s,
        HelperVpcId=helper_vpc.vpc_id,
        WorkloadVpcId=workload_vpc.vpc_id,
        HelperSubnetId=helper_subnet.subnet_id,
        WorkloadSubnetId=workload_subnet.subnet_id,
        HelperSecurityGroupId=helper_sg.security_group_id,
        WorkloadSecurityGroupId=workload_sg.security_group_id,
        AutoScalingGroupName=group.auto_scaling_group_name,
        LaunchTemplateId=template.launch_template_id,
        NetworkLoadBalancerArn=nlb.load_balancer_arn,
        TargetGroupArn=target_group.target_group_arn,
        InstanceProfileArn=profile.attr_arn,
    )


def secondary_eni_asg(s: cdk.Stack, *, prefix: str) -> None:
    """A helper Auto Scaling group across two VPCs, a KMS-encrypted secret, an SSH-denying ACL."""
    key = kms.Key(s, "KmsKey", description="KMS key for Secrets Manager secret encryption",
                  enable_key_rotation=True, removal_policy=DESTROY)
    primary_vpc = make_vpc(s, "PrimaryVpc", ("QuartzHelperSubnet", PRIVATE, 24),
                           ("Public", PUBLIC, 24), cidr="172.25.0.0/16", max_azs=2, nat_gateways=1)
    customer_vpc = make_vpc(s, "CustomerVpc", ("CustomerSubnet", ISOLATED, 24), cidr="10.1.0.0/16",
                            max_azs=2, nat_gateways=0)
    helper_sg = ec2.SecurityGroup(s, "QuartzHelperSg", vpc=primary_vpc,
                                  description="Security group for Quartz helper instance")
    helper_sg.add_ingress_rule(ec2.Peer.ipv4("172.25.0.0/16"), ec2.Port.tcp(22),
                               "Allow SSH from VPC CIDR")
    customer_sg = ec2.SecurityGroup(s, "CustomerSg", vpc=customer_vpc,
                                    description="No ingress security group for customer VPC")
    role = iam.Role(s, "InstanceRole", assumed_by=_service("ec2"),
                    managed_policies=[_managed(_SSM_CORE)])
    role.add_to_policy(iam.PolicyStatement(
        actions=["ec2:CreateNetworkInterface", "ec2:AttachNetworkInterface",
                 "ec2:DescribeNetworkInterfaces", "ec2:DescribeInstances",
                 "ec2:ModifyNetworkInterfaceAttribute", "ec2:CreateTags"],
        resources=["*"]))
    key.grant_decrypt(role)
    profile = iam.CfnInstanceProfile(s, "InstanceProfile", roles=[role.role_name])
    primary_subnet = primary_vpc.private_subnets[0]
    customer_subnet = customer_vpc.isolated_subnets[0]

    acl = ec2.NetworkAcl(s, "PrivateSubnetNacl", vpc=primary_vpc,
                         subnet_selection=ec2.SubnetSelection(subnets=[primary_subnet]))
    acl.add_entry("DenySSHInbound", rule_number=50, cidr=ec2.AclCidr.any_ipv4(),
                  traffic=ec2.AclTraffic.tcp_port(22),
                  direction=ec2.TrafficDirection.INGRESS, rule_action=ec2.Action.DENY)
    acl.add_entry("AllowVpcInbound", rule_number=100, cidr=ec2.AclCidr.ipv4("172.25.0.0/16"),
                  traffic=ec2.AclTraffic.all_traffic(),
                  direction=ec2.TrafficDirection.INGRESS, rule_action=ec2.Action.ALLOW)
    acl.add_entry("AllowAllOutbound", rule_number=100, cidr=ec2.AclCidr.any_ipv4(),
                  traffic=ec2.AclTraffic.all_traffic(),
                  direction=ec2.TrafficDirection.EGRESS, rule_action=ec2.Action.ALLOW)

    image = ec2.MachineImage.latest_amazon_linux2023(cpu_type=ec2.AmazonLinuxCpuType.X86_64)
    cluster_arn = (f"arn:{s.partition}:sagemaker:{s.region}:{s.account}:cluster/" "basaltcluste")
    user_data = ec2.UserData.for_linux()
    user_data.add_commands(
        "INSTANCE_ID=$(ec2-metadata --instance-id | cut -d ' ' -f 2)",
        f'REGION="{s.region}"',
        f'CUSTOMER_SUBNET="{customer_subnet.subnet_id}"',
        f'CUSTOMER_SG="{customer_sg.security_group_id}"',
        "ENI_ID=$(aws ec2 create-network-interface --subnet-id $CUSTOMER_SUBNET "
        "--groups $CUSTOMER_SG --region $REGION "
        "--query NetworkInterface.NetworkInterfaceId --output text)",
        "aws ec2 wait network-interface-available --network-interface-ids $ENI_ID "
        "--region $REGION",
        "aws ec2 attach-network-interface --network-interface-id $ENI_ID "
        "--instance-id $INSTANCE_ID --device-index 1 --region $REGION",
        f'aws ec2 create-tags --resources $ENI_ID --tags "Key=ClusterArn,Value={cluster_arn}" '
        '"Key=InstanceGroupName,Value=quartzgroup1" --region $REGION',
    )
    template = ec2.CfnLaunchTemplate(
        s, "LaunchTemplate",
        launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
            instance_type="t3.micro",
            image_id=image.get_image(s).image_id,
            iam_instance_profile=ec2.CfnLaunchTemplate.IamInstanceProfileProperty(
                name=profile.ref),
            user_data=cdk.Fn.base64(user_data.render()),
            block_device_mappings=[ec2.CfnLaunchTemplate.BlockDeviceMappingProperty(
                device_name="/dev/xvda",
                ebs=ec2.CfnLaunchTemplate.EbsProperty(volume_size=100, volume_type="gp3",
                                                      delete_on_termination=True,
                                                      encrypted=True))],
            metadata_options=ec2.CfnLaunchTemplate.MetadataOptionsProperty(
                http_tokens="required", http_put_response_hop_limit=2,
                http_endpoint="enabled"),
            network_interfaces=[ec2.CfnLaunchTemplate.NetworkInterfaceProperty(
                device_index=0, subnet_id=primary_subnet.subnet_id,
                groups=[helper_sg.security_group_id], delete_on_termination=True,
                associate_public_ip_address=False)],
            tag_specifications=[
                ec2.CfnLaunchTemplate.TagSpecificationProperty(
                    resource_type="instance",
                    tags=[cdk.CfnTag(key="ClusterArn", value=cluster_arn),
                          cdk.CfnTag(key="InstanceGroupName", value="quartzgroup1"),
                          cdk.CfnTag(key="RIG-Version", value="2"),
                          cdk.CfnTag(key="Customer-Subnet", value=customer_subnet.subnet_id),
                          cdk.CfnTag(key="Customer-SG", value=customer_sg.security_group_id)]),
                ec2.CfnLaunchTemplate.TagSpecificationProperty(
                    resource_type="network-interface",
                    tags=[cdk.CfnTag(key="ClusterArn", value=cluster_arn),
                          cdk.CfnTag(key="InstanceGroupName", value="quartzgroup1")]),
            ],
        ),
    )
    group = autoscaling.CfnAutoScalingGroup(
        s, "AutoScalingGroup", min_size="0", max_size="1", desired_capacity="0",
        vpc_zone_identifier=[primary_subnet.subnet_id],
        launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
            launch_template_id=template.ref, version=template.attr_latest_version_number),
        auto_scaling_group_name=f"{prefix}-quartz-helper-asg-quartzgroup1",
        tags=[autoscaling.CfnAutoScalingGroup.TagPropertyProperty(
            key=k, value=v, propagate_at_launch=True)
            for k, v in (("ClusterArn", cluster_arn), ("InstanceGroupName", "quartzgroup1"),
                         ("RIG-Version", "2"))])
    secret = secretsmanager.Secret(
        s, "QuartzSecret", secret_name=f"{prefix}-quartz-certificate-quartzgroup1",
        description="Quartz Proxy Server Certificate and private key", encryption_key=key,
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"certificate": "PLACEHOLDER_CERTIFICATE",
                                               "privateKey": "PLACEHOLDER_PRIVATE_KEY"}),
            generate_string_key="password"))
    cdk.Tags.of(secret).add("ClusterArn", cluster_arn)
    cdk.Tags.of(secret).add("InstanceGroupName", "quartzgroup1")
    secret.grant_read(role)

    exports(
        s,
        PrimaryVpcId=primary_vpc.vpc_id,
        CustomerVpcId=customer_vpc.vpc_id,
        QuartzHelperSecurityGroupId=helper_sg.security_group_id,
        CustomerSecurityGroupId=customer_sg.security_group_id,
        InstanceRoleArn=role.role_arn,
        InstanceProfileName=profile.ref,
        LaunchTemplateId=template.ref,
        AutoScalingGroupName=group.ref,
        QuartzSecretArn=secret.secret_arn,
        QuartzSecretName=secret.secret_name,
        KmsKeyId=key.key_id,
        PrimarySubnetId=primary_subnet.subnet_id,
        CustomerSubnetId=customer_subnet.subnet_id,
        ClusterArn=cluster_arn,
        NatGatewayId=primary_vpc.public_subnets[0].node.find_child("NATGateway").ref,
        PrivateSubnetNaclId=acl.network_acl_id,
    )


#: The image tags the task definitions reference; nothing pushes either.
WEB_APP_IMAGE_TAG = "a3f1c2e4-9b7d-4e8a-b6f0-2d5c8e1a4f7b_service_main"
INFERENCE_SERVICE_TAG = "dev_build_service_latest"
INFERENCE_SIDECAR_TAG = "dev_build_sidecar_latest"
#: The one tag the inference repository is seeded with after deploy.
INFERENCE_SEEDED_TAG = "dev_build_service_main"
#: The required variable the crash-looping container exits without.
MISSING_VARIABLE_LINES = (
    "ERROR Missing required environment variable: DB_PASSWORD",
    "ERROR Failed to connect to database: Connection refused",
    "ERROR Database host not reachable: garnet-db.internal",
    "ERROR Application startup failed. Exiting with code 1",
)

_EXECUTION_POLICY = "service-role/AmazonECSTaskExecutionRolePolicy"
_ECR_PULL = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability",
             "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]


def _role(scope, logical, name, service="ecs-tasks.amazonaws.com", *managed):
    return iam.Role(scope, logical, role_name=name, assumed_by=iam.ServicePrincipal(service),
                    managed_policies=[_managed(m)
                                      for m in managed])


def _repository(scope, logical, name) -> ecr.Repository:
    return ecr.Repository(scope, logical, repository_name=name, image_scan_on_push=False,
                          encryption=ecr.RepositoryEncryption.AES_256,
                          image_tag_mutability=ecr.TagMutability.MUTABLE,
                          removal_policy=DESTROY, empty_on_delete=True)


def fargate_web_app(s: cdk.Stack, *, prefix: str) -> None:
    """A Fargate web service behind an internal ALB with a regional web ACL and access logs."""
    vpc = make_vpc(s, "VPC", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24), max_azs=2,
                   nat_gateways=2)
    server_logs = secure_bucket(s, "ServerAccessLogsBucket",
                                bucket_name=f"{prefix}-server-access-logs")
    alb_logs = secure_bucket(s, "ALBAccessLogsBucket", bucket_name=f"{prefix}-alb-logs",
                             server_access_logs_bucket=server_logs,
                             server_access_logs_prefix="alb-access-logs/")
    repository = _repository(s, "ECRRepository", f"{prefix}-ecrrepo")
    app_secret = cdk.aws_secretsmanager.Secret(
        s, "AppSecret", secret_name=f"{prefix}-app-secret",
        description="Application distribution secret", removal_policy=DESTROY)
    execution = _role(s, "TaskExecutionRole", f"{prefix}-web-task-exec",
                      "ecs-tasks.amazonaws.com", _EXECUTION_POLICY)
    execution.add_to_policy(iam.PolicyStatement(actions=_ECR_PULL, resources=["*"]))
    task_role = _role(s, "TaskRole", f"{prefix}-web-task")
    task_role.add_to_policy(iam.PolicyStatement(actions=["secretsmanager:GetSecretValue"],
                                                resources=[app_secret.secret_arn]))
    log_group = logs.LogGroup(s, "FargateLogGroup",
                              log_group_name=f"/ecs/{prefix}-fargate-task",
                              retention=logs.RetentionDays.ONE_WEEK,
                              removal_policy=DESTROY)
    cluster = ecs.Cluster(s, "EcsCluster", cluster_name=f"{prefix}-web-cluster", vpc=vpc,
                          container_insights_v2=ecs.ContainerInsights.ENABLED)
    alb_sg = ec2.SecurityGroup(s, "ALBSecurityGroup", vpc=vpc,
                               description="Security group for Application Load Balancer")
    for port in (80, 443):
        alb_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(port),
                                f"Allow port {port} from inside the VPC")
    task_sg = ec2.SecurityGroup(s, "FargateSecurityGroup", vpc=vpc,
                                description="Security group for Fargate service")
    task_sg.add_ingress_rule(alb_sg, ec2.Port.tcp(8501), "Allow traffic from ALB on port 8501")
    private = select(PRIVATE)
    alb = elbv2.ApplicationLoadBalancer(s, "ALB", load_balancer_name=f"{prefix}-webalb",
                                        vpc=vpc, internet_facing=False, security_group=alb_sg,
                                        vpc_subnets=private)
    alb.log_access_logs(alb_logs, "alb-logs")
    written_by(alb_logs, alb)
    target_group = elbv2.ApplicationTargetGroup(
        s, "TargetGroup", target_group_name=f"{prefix}-webtg", vpc=vpc, port=8501,
        protocol=elbv2.ApplicationProtocol.HTTP, target_type=elbv2.TargetType.IP,
        health_check=elbv2.HealthCheck(enabled=True, path="/", protocol=elbv2.Protocol.HTTP,
                                       healthy_threshold_count=2, unhealthy_threshold_count=3,
                                       timeout=Duration.seconds(5),
                                       interval=Duration.seconds(30)),
        deregistration_delay=Duration.seconds(30))
    # The listener is not opened to any address; the group admits only the VPC.
    alb.add_listener("HTTPListener", port=80, protocol=elbv2.ApplicationProtocol.HTTP,
                     open=False,
                     default_target_groups=[target_group])
    web_acl = wafv2.CfnWebACL(
        s, "ALBWebACL", scope="REGIONAL",
        default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
        visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
            sampled_requests_enabled=True, cloud_watch_metrics_enabled=True,
            metric_name="ALBWebACL"),
        rules=[])
    wafv2.CfnWebACLAssociation(s, "ALBWebACLAssociation",
                               resource_arn=alb.load_balancer_arn,
                               web_acl_arn=web_acl.attr_arn)
    task_definition = ecs.FargateTaskDefinition(
        s, "FargateTaskDefinition", family=f"{prefix}-fargate-task", cpu=4096,
        memory_limit_mib=30720, task_role=task_role, execution_role=execution)
    container = task_definition.add_container(
        "Container", container_name="Container",
        image=ecs.ContainerImage.from_ecr_repository(repository, WEB_APP_IMAGE_TAG),
        cpu=4096, memory_limit_mib=30720, essential=True, readonly_root_filesystem=True,
        logging=ecs.LogDrivers.aws_logs(stream_prefix="FargateApp", log_group=log_group,
                                        mode=ecs.AwsLogDriverMode.NON_BLOCKING))
    container.add_port_mappings(ecs.PortMapping(container_port=8501, host_port=8501,
                                                protocol=ecs.Protocol.TCP))
    service = ecs.FargateService(
        s, "FargateService", service_name=f"{prefix}-fargate-service", cluster=cluster,
        task_definition=task_definition, desired_count=0, assign_public_ip=False,
        security_groups=[task_sg], vpc_subnets=private,
        health_check_grace_period=Duration.seconds(60),
        platform_version=ecs.FargatePlatformVersion.LATEST)
    service.attach_to_application_target_group(target_group)

    exports(
        s,
        VPCId=vpc.vpc_id,
        ECRRepositoryName=repository.repository_name,
        ECRRepositoryUri=repository.repository_uri,
        ECSClusterName=cluster.cluster_name,
        AlbArn=alb.load_balancer_arn,
        ALBDnsName=alb.load_balancer_dns_name,
        WebAclArn=web_acl.attr_arn,
        AppSecretArn=app_secret.secret_arn,
        FargateServiceName=service.service_name,
        FargateSecurityGroupId=task_sg.security_group_id,
        TargetGroupArn=target_group.target_group_arn,
        TaskDefinitionFamily=task_definition.family,
        PrivateSubnetId1=vpc.private_subnets[0].subnet_id,
        PrivateSubnetId2=vpc.private_subnets[1].subnet_id,
        ContainerImageTag=WEB_APP_IMAGE_TAG,
    )


def cache_transit(s: cdk.Stack, *, prefix: str) -> None:
    """Six Fargate tasks and a Memcached cluster in another VPC, joined by a transit gateway."""
    ecs_vpc = make_vpc(s, "EcsVpc", ("Private", PRIVATE, 20), ("Public", PUBLIC, 20),
                       vpc_name=f"{prefix}-appservice-vpc", cidr="10.131.0.0/16", max_azs=2,
                       enable_dns_hostnames=True, enable_dns_support=True)
    for k, v in (("Name", "Prod-AppService-VPC"), ("DeploymentType", "Pipelines"),
                 ("SoftwareType", "Infrastructure"), ("TargetAlias", "VpcStack")):
        cdk.Tags.of(ecs_vpc).add(k, v)
    cache_vpc = make_vpc(s, "CacheVpc", ("Private", ISOLATED, 26), vpc_name=f"{prefix}-cache-vpc",
                         cidr="10.137.0.0/24", max_azs=1, enable_dns_hostnames=True,
                         enable_dns_support=True)
    cdk.Tags.of(cache_vpc).add("Name", "Cache-ElastiCache-VPC")
    tgw = ec2.CfnTransitGateway(
        s, "TransitGateway", description="Gateway for VPC to access caches",
        amazon_side_asn=64512, auto_accept_shared_attachments="enable",
        default_route_table_association="disable", default_route_table_propagation="disable",
        vpn_ecmp_support="enable", dns_support="enable",
        tags=[cdk.CfnTag(key="Name", value="Cache-CacheCluster-ABC"),
              cdk.CfnTag(key="TargetAlias", value="TransitGatewayStack"),
              cdk.CfnTag(key="SoftwareType", value="Infrastructure")])
    ecs_attachment = ec2.CfnTransitGatewayAttachment(
        s, "EcsVpcAttachment", transit_gateway_id=tgw.attr_id, vpc_id=ecs_vpc.vpc_id,
        subnet_ids=[subnet.subnet_id for subnet in ecs_vpc.private_subnets],
        tags=[cdk.CfnTag(key="Name", value="Cache-CacheCluster-ABC-Attachment-Client-Prod")])
    cache_attachment = ec2.CfnTransitGatewayAttachment(
        s, "CacheVpcAttachment", transit_gateway_id=tgw.attr_id, vpc_id=cache_vpc.vpc_id,
        subnet_ids=[subnet.subnet_id for subnet in cache_vpc.isolated_subnets],
        tags=[cdk.CfnTag(key="Name", value="Cache-CacheCluster-ABC-Attachment-Cache")])
    client_rt = ec2.CfnTransitGatewayRouteTable(
        s, "EcsClientRouteTable", transit_gateway_id=tgw.attr_id,
        tags=[cdk.CfnTag(key="Name", value="Cache-CacheCluster-ABC-Client-RouteTable-Prod")])
    cache_rt = ec2.CfnTransitGatewayRouteTable(
        s, "CacheRouteTable", transit_gateway_id=tgw.attr_id,
        tags=[cdk.CfnTag(key="Name", value="Cache-CacheCluster-ABC-RouteTable")])
    client_assoc = ec2.CfnTransitGatewayRouteTableAssociation(
        s, "EcsClientRouteTableAssociation",
        transit_gateway_attachment_id=ecs_attachment.attr_id,
        transit_gateway_route_table_id=client_rt.attr_transit_gateway_route_table_id)
    cache_assoc = ec2.CfnTransitGatewayRouteTableAssociation(
        s, "CacheRouteTableAssociation",
        transit_gateway_attachment_id=cache_attachment.attr_id,
        transit_gateway_route_table_id=cache_rt.attr_transit_gateway_route_table_id)
    to_cache = ec2.CfnTransitGatewayRoute(
        s, "EcsClientToCacheRoute",
        transit_gateway_route_table_id=client_rt.attr_transit_gateway_route_table_id,
        destination_cidr_block="10.137.0.0/24",
        transit_gateway_attachment_id=cache_attachment.attr_id)
    propagation = ec2.CfnTransitGatewayRouteTablePropagation(
        s, "EcsClientRoutePropagation",
        transit_gateway_attachment_id=ecs_attachment.attr_id,
        transit_gateway_route_table_id=client_rt.attr_transit_gateway_route_table_id)
    service_sg = ec2.SecurityGroup(
        s, "EcsServiceSecurityGroup", vpc=ecs_vpc,
        description="AppService-ECSService/Service/Service/SecurityGroup",
        security_group_name=f"{prefix}-appservice-service-sg")
    for port, label in ((8443, "8443"), (7979, "AppServicePort")):
        service_sg.add_ingress_rule(ec2.Peer.ipv4("10.131.0.0/16"), ec2.Port.tcp(port),
                                    f"from 10.131.0.0/16:{label}")
    cdk.Tags.of(service_sg).add("SoftwareType", "Long-Running Server-Side Software")
    cdk.Tags.of(service_sg).add("TargetAlias", "EcsServiceStack")
    cache_sg = ec2.SecurityGroup(
        s, "ElastiCacheSecurityGroup", vpc=cache_vpc,
        description="SecurityGroup for ElastiCache",
        security_group_name=f"{prefix}-cache-sg")
    for cidr in ("10.137.0.0/24", "10.131.0.0/16"):
        cache_sg.add_ingress_rule(ec2.Peer.ipv4(cidr), ec2.Port.tcp(11211),
                                  "APP Cache ingress rule")
    for k, v in (("SoftwareType", "Long-Running Server-Side Software"),
                 ("TargetAlias", "CacheClusterStack"), ("DeploymentType", "Pipelines")):
        cdk.Tags.of(cache_sg).add(k, v)
    subnet_group = elasticache.CfnSubnetGroup(
        s, "CacheSubnetGroup", description="SubnetGroup for APP ElastiCache cluster",
        subnet_ids=[subnet.subnet_id for subnet in cache_vpc.isolated_subnets],
        cache_subnet_group_name=f"{prefix}-cache")
    cache = elasticache.CfnCacheCluster(
        s, "ElastiCacheCluster", cache_node_type="cache.t3.small", engine="memcached",
        num_cache_nodes=1, cluster_name=f"{prefix}-cache", engine_version="1.6.12",
        cache_subnet_group_name=subnet_group.cache_subnet_group_name,
        vpc_security_group_ids=[cache_sg.security_group_id],
        preferred_maintenance_window="sun:05:00-sun:06:00", transit_encryption_enabled=True)
    for dependency in (subnet_group, cache_attachment, cache_assoc, client_assoc, to_cache,
                       propagation):
        cache.node.add_dependency(dependency)
    cluster = ecs.Cluster(s, "EcsCluster", vpc=ecs_vpc,
                          cluster_name=f"{prefix}-appservice-cluster",
                          enable_fargate_capacity_providers=True)
    task_definition = ecs.FargateTaskDefinition(
        s, "TaskDefinition", family=f"{prefix}-appservice-taskdef", cpu=2048,
        memory_limit_mib=4096, ephemeral_storage_gib=21)
    task_definition.add_container(
        "Application",
        image=ecs.ContainerImage.from_registry("public.ecr.aws/nginx/nginx:1.30"),
        cpu=0, logging=ecs.LogDrivers.aws_logs(stream_prefix="Application"))
    task_definition.add_container(
        "FireLensContainer",
        image=ecs.ContainerImage.from_registry(
            "public.ecr.aws/aws-observability/aws-for-fluent-bit:latest"),
        cpu=512, memory_limit_mib=512,
        logging=ecs.LogDrivers.aws_logs(stream_prefix="FireLens"))
    service = ecs.FargateService(
        s, "EcsService", cluster=cluster, task_definition=task_definition,
        desired_count=6, platform_version=ecs.FargatePlatformVersion.VERSION1_4,
        security_groups=[service_sg],
        vpc_subnets=select(PRIVATE))

    export(s, "EcsClusterName", cluster.cluster_name)
    export(s, "EcsClusterArn", cluster.cluster_arn)
    export(s, "TaskDefinitionArn", task_definition.task_definition_arn)
    export(s, "EcsServiceName", service.service_name)
    export(s, "EcsServiceArn", service.service_arn)
    export(s, "EcsVpcId", ecs_vpc.vpc_id)
    export(s, "CacheVpcId", cache_vpc.vpc_id)
    export(s, "TransitGatewayId", tgw.attr_id)
    export(s, "ElastiCacheClusterId", cache.ref)
    export(s, "EcsPrivateSubnet1Id", ecs_vpc.private_subnets[0].subnet_id)
    export(s, "EcsPrivateSubnet2Id", ecs_vpc.private_subnets[1].subnet_id)
    export(s, "CachePrivateSubnet1Id", cache_vpc.isolated_subnets[0].subnet_id)
    export(s, "EcsVpcTgwAttachmentId", ecs_attachment.attr_id)
    export(s, "CacheVpcTgwAttachmentId", cache_attachment.attr_id)
    export(s, "EcsClientTgwRouteTableId", client_rt.attr_transit_gateway_route_table_id)
    export(s, "CacheTgwRouteTableId", cache_rt.attr_transit_gateway_route_table_id)
    export(s, "EcsServiceSecurityGroupId", service_sg.security_group_id)
    export(s, "ElastiCacheSecurityGroupId", cache_sg.security_group_id)
    for index, subnet in enumerate(ecs_vpc.public_subnets[:2], start=1):
        export(s, f"EcsNatGateway{index}Id", subnet.node.find_child("NATGateway").ref)


def firelens_service(s: cdk.Stack, *, prefix: str) -> None:
    """An idle Fargate service whose containers log through a FireLens router."""
    vpc = make_vpc(s, "Vpc", ("Private", ISOLATED, 19), vpc_name=f"{prefix}-ecs-vpc", max_azs=3,
                   nat_gateways=0)
    group = ec2.SecurityGroup(s, "EcsServiceSecurityGroup", vpc=vpc,
                              security_group_name=f"{prefix}-quartz-service-sg",
                              description="Security group for ECS service tasks")
    repository = _repository(s, "EcrRepository", f"{prefix}-quartz-repo")
    cluster = ecs.Cluster(s, "EcsCluster", cluster_name=f"{prefix}-quartz-cluster", vpc=vpc,
                          container_insights_v2=ecs.ContainerInsights.ENABLED)
    execution = _role(s, "TaskExecutionRole", f"{prefix}-quartz-task-exec",
                      "ecs-tasks.amazonaws.com", _EXECUTION_POLICY)
    repository.grant_pull(execution)
    task_role = _role(s, "TaskRole", f"{prefix}-quartz-task")
    task_definition = ecs.FargateTaskDefinition(
        s, "TaskDefinition", family=f"{prefix}-quartz-task-def", cpu=2048,
        memory_limit_mib=4096, execution_role=execution, task_role=task_role,
        ephemeral_storage_gib=40)
    task_definition.add_firelens_log_router(
        "log-router",
        image=ecs.ContainerImage.from_registry(
            f"{repository.repository_uri}:fluent-bit-latest"),
        cpu=256, memory_reservation_mib=512, essential=False,
        firelens_config=ecs.FirelensConfig(type=ecs.FirelensLogRouterType.FLUENTBIT),
        logging=ecs.LogDrivers.aws_logs(stream_prefix="log-router"))
    container = task_definition.add_container(
        "service",
        image=ecs.ContainerImage.from_registry(f"{repository.repository_uri}:latest"),
        cpu=1792, memory_limit_mib=4096, essential=True, logging=ecs.LogDrivers.firelens())
    container.add_port_mappings(ecs.PortMapping(container_port=8443, protocol=ecs.Protocol.TCP))
    service = ecs.FargateService(
        s, "EcsService", service_name=f"{prefix}-quartz-service", cluster=cluster,
        task_definition=task_definition, desired_count=0,
        platform_version=ecs.FargatePlatformVersion.VERSION1_4, security_groups=[group],
        vpc_subnets=select(ISOLATED),
        health_check_grace_period=Duration.seconds(60),
        circuit_breaker=ecs.DeploymentCircuitBreaker(enable=True, rollback=True),
        enable_execute_command=False, assign_public_ip=False)

    exports(
        s,
        EcsClusterName=cluster.cluster_name,
        EcsServiceName=service.service_name,
        TaskDefinitionArn=task_definition.task_definition_arn,
        EcrRepositoryUri=repository.repository_uri,
        EcrRepositoryName=repository.repository_name,
        VpcId=vpc.vpc_id,
        SecurityGroupId=group.security_group_id,
    )


def crash_loop_service(s: cdk.Stack, *, prefix: str) -> None:
    """A Fargate service whose container exits 1 because its database password is never set."""
    vpc = make_vpc(s, "Vpc", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24),
                   vpc_name=f"{prefix}-garnet-vpc", max_azs=2, nat_gateways=1)
    log_group = logs.LogGroup(s, "AppStdoutLogGroup",
                              log_group_name=f"{prefix}-GarnetPlugin-AppContainer-STDOUT",
                              retention=logs.RetentionDays.ONE_MONTH,
                              removal_policy=DESTROY)
    execution = _role(s, "TaskExecutionRole", f"{prefix}-garnet-task-exec",
                      "ecs-tasks.amazonaws.com", _EXECUTION_POLICY)
    cluster = ecs.Cluster(s, "Cluster", cluster_name=f"{prefix}-garnet-cluster", vpc=vpc)
    task_definition = ecs.FargateTaskDefinition(
        s, "TaskDefinition", family=f"{prefix}-garnet-service", cpu=256,
        memory_limit_mib=512, execution_role=execution)
    checks = "; ".join(f'echo "{line}"' for line in MISSING_VARIABLE_LINES)
    task_definition.add_container(
        "service",
        image=ecs.ContainerImage.from_registry("public.ecr.aws/amazonlinux/amazonlinux:latest"),
        essential=True,
        environment={},
        command=["sh", "-c", f'if [ -z "$DB_PASSWORD" ]; then {checks}; exit 1; fi; '
                             'echo "INFO Application started successfully"'],
        logging=ecs.LogDrivers.aws_logs(stream_prefix="service", log_group=log_group))
    private = select(PRIVATE)
    service = ecs.FargateService(
        s, "Service", service_name=f"{prefix}-garnet-service", cluster=cluster,
        task_definition=task_definition, desired_count=0, assign_public_ip=False,
        vpc_subnets=private)

    exports(
        s,
        ClusterName=cluster.cluster_name,
        ClusterArn=cluster.cluster_arn,
        ServiceName=service.service_name,
        ServiceArn=service.service_arn,
        TaskDefinitionArn=task_definition.task_definition_arn,
        TaskSubnetIds=",".join(vpc.select_subnets( subnet_type=PRIVATE).subnet_ids),
        TaskSecurityGroupId=service.connections.security_groups[0].security_group_id,
        AppStdoutLogGroupName=log_group.log_group_name,
    )


def cross_account_image(s: cdk.Stack, *, prefix: str) -> None:
    """An idle Fargate service in isolated subnets whose images live in another account."""
    vpc = make_vpc(s, "CobaltVpc", ("cobalt-private-subnet", ISOLATED, 24),
                   vpc_name=f"{prefix}-cobalt-vpc", cidr="10.0.0.0/16", max_azs=2, nat_gateways=0,
                   enable_dns_hostnames=True, enable_dns_support=True)
    cdk.Tags.of(vpc).add("Name", "cobalt-vpc")
    private = vpc.isolated_subnets
    endpoint_sg = ec2.SecurityGroup(s, "EndpointSecurityGroup", vpc=vpc,
                                    description="Security group for VPC endpoints",
                                    allow_all_outbound=False)
    endpoint_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(443), "HTTPS from VPC")
    for logical, service in (("EcrApiEndpoint", ec2.InterfaceVpcEndpointAwsService.ECR),
                             ("EcrDkrEndpoint", ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER),
                             ("CloudWatchLogsEndpoint",
                              ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS)):
        vpc.add_interface_endpoint(logical, service=service,
                                   subnets=ec2.SubnetSelection(subnets=private),
                                   security_groups=[endpoint_sg])
    vpc.add_gateway_endpoint("S3Endpoint", service=ec2.GatewayVpcEndpointAwsService.S3,
                             subnets=[ec2.SubnetSelection(subnets=private)])
    task_sg = ec2.SecurityGroup(s, "EcsSecurityGroup", vpc=vpc,
                                security_group_name=f"{prefix}-cobalt-ecs-sg",
                                description="Security group for Cobalt ECS service")
    task_sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(8080),
                             "Allow traffic from VPC")
    cdk.Tags.of(task_sg).add("Name", "cobalt-ecs-sg")
    task_role = _role(s, "EcsTaskRole", f"{prefix}-cobalt-task")
    execution = _role(s, "EcsExecutionRole", f"{prefix}-cobalt-task-exec",
                      "ecs-tasks.amazonaws.com", _EXECUTION_POLICY)
    log_prefix = f"{prefix}-CobaltService-Staging"
    execution.add_to_policy(iam.PolicyStatement(
        actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        resources=[f"arn:{s.partition}:logs:{s.region}:{s.account}:log-group:"
                   f"{log_prefix}-*"]))
    execution.add_to_policy(iam.PolicyStatement(actions=_ECR_PULL, resources=["*"]))
    # Referenced by name; nothing creates these groups.
    imported = {
        key: logs.LogGroup.from_log_group_name(s, logical, f"{log_prefix}-{suffix}")
        for key, logical, suffix in (
            ("AppContainerStdout", "AppContainerStdoutLogGroup", "AppContainer-STDOUT"),
            ("ApplicationLogs", "ApplicationLogsLogGroup", "ApplicationLogs"),
            ("RequestLogs", "RequestLogsLogGroup", "RequestLogs"),
            ("ServiceMetrics", "ServiceMetricsLogGroup", "ServiceMetrics"))
    }
    cluster = ecs.Cluster(s, "EcsCluster", cluster_name=f"{prefix}-cobalt-cluster", vpc=vpc)
    task_definition = ecs.FargateTaskDefinition(
        s, "TaskDefinition", family=f"{prefix}-cobalt-service", cpu=2048,
        memory_limit_mib=4096, task_role=task_role, execution_role=execution)
    foreign = f"123456789012.dkr.ecr.{s.region}.amazonaws.com/cobaltrepo"
    container = task_definition.add_container(
        "service", image=ecs.ContainerImage.from_registry(f"{foreign}:latest_cobalt_main"),
        cpu=1792, memory_limit_mib=4096, essential=True,
        logging=ecs.LogDrivers.firelens(options={}))
    container.add_port_mappings(ecs.PortMapping(container_port=8080, protocol=ecs.Protocol.TCP))
    task_definition.add_firelens_log_router(
        "log-router",
        image=ecs.ContainerImage.from_registry(f"{foreign}:latest_fluent-bit_main"),
        firelens_config=ecs.FirelensConfig(type=ecs.FirelensLogRouterType.FLUENTBIT),
        cpu=256, memory_reservation_mib=512, essential=False,
        logging=ecs.LogDrivers.aws_logs(stream_prefix="Application-service-firelens",
                                        log_group=imported["AppContainerStdout"]),
        environment={"HOSTNAME": "", "CLOUDWATCH_ENDPOINT": ""})
    service = ecs.FargateService(
        s, "EcsService", service_name=f"{prefix}-cobalt-service", cluster=cluster,
        task_definition=task_definition, desired_count=0,
        platform_version=ecs.FargatePlatformVersion.VERSION1_4,
        vpc_subnets=ec2.SubnetSelection(subnets=private), security_groups=[task_sg],
        assign_public_ip=False, circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True))

    export(s, "AccountId", s.account)
    export(s, "VpcId", vpc.vpc_id)
    export(s, "ClusterName", cluster.cluster_name)
    export(s, "ServiceName", service.service_name)
    export(s, "TaskDefinitionArn", task_definition.task_definition_arn)
    for key, group in imported.items():
        export(s, f"{key}LogGroupName", group.log_group_name)


def gpu_inference(s: cdk.Stack, *, prefix: str) -> None:
    """An idle GPU service on an empty EC2 capacity provider, referencing tags its repo lacks."""
    vpc = make_vpc(s, "EcsVpc", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24), max_azs=2,
                   nat_gateways=1)
    log_group = logs.LogGroup(s, "EcsLogGroup", log_group_name=f"/ecs/{prefix}-inference",
                              retention=logs.RetentionDays.ONE_WEEK,
                              removal_policy=DESTROY)
    repository = _repository(s, "EcrRepository", f"{prefix}-basaltrepo")
    execution = _role(s, "TaskExecutionRole", f"{prefix}-inference-task-exec",
                      "ecs-tasks.amazonaws.com", _EXECUTION_POLICY)
    repository.grant_pull(execution)
    log_group.grant_write(execution)
    task_role = _role(s, "TaskRole", f"{prefix}-inference-task")
    task_role.add_to_policy(iam.PolicyStatement(actions=["cloudwatch:PutMetricData"],
                                                resources=["*"]))
    default_cluster = ecs.Cluster(s, "DefaultCluster", cluster_name=f"{prefix}-default", vpc=vpc)
    app_cluster = ecs.Cluster(s, "AppCluster", cluster_name=f"{prefix}-inference-cluster", vpc=vpc)
    instance_role = iam.Role(
        s, "InstanceRole", assumed_by=_service("ec2"),
        managed_policies=[_managed(m) for m in (
            "service-role/AmazonEC2ContainerServiceforEC2Role",
            "AmazonSSMManagedInstanceCore")])
    user_data = ec2.UserData.for_linux()
    user_data.add_commands(
        f"echo ECS_CLUSTER={app_cluster.cluster_name} >> /etc/ecs/ecs.config",
        "mkdir -p /opt/models/basalt-tensorrt-fp8",
        "chown -R 1000:1000 /opt/models")
    template = ec2.LaunchTemplate(
        s, "GpuLaunchTemplate", instance_type=ec2.InstanceType("g4dn.2xlarge"),
        machine_image=ecs.EcsOptimizedImage.amazon_linux2023(ecs.AmiHardwareType.GPU),
        role=instance_role, user_data=user_data, require_imdsv2=True)
    capacity = autoscaling.AutoScalingGroup(
        s, "GpuCapacity", vpc=vpc, launch_template=template, desired_capacity=0,
        min_capacity=0, max_capacity=1,
        vpc_subnets=select(PRIVATE))
    app_cluster.add_asg_capacity_provider(ecs.AsgCapacityProvider(
        s, "GpuCapacityProvider", auto_scaling_group=capacity,
        enable_managed_termination_protection=False))
    task_definition = ecs.Ec2TaskDefinition(
        s, "TaskDefinition", family=f"{prefix}-inference-task-def",
        network_mode=ecs.NetworkMode.AWS_VPC, task_role=task_role, execution_role=execution)
    task_definition.add_volume(name="models-volume", host=ecs.Host(source_path="/opt/models"))
    task_definition.add_firelens_log_router(
        "FluentBitContainer",
        image=ecs.ContainerImage.from_ecr_repository(repository, INFERENCE_SIDECAR_TAG),
        cpu=512, memory_reservation_mib=512, essential=True,
        environment={"MODEL_ID": "Flint", "LOG_REGION": s.region,
                     "MODEL_GROUP": "BasaltInference"},
        logging=ecs.AwsLogDriver(log_group=log_group, stream_prefix="FluentBit-"),
        health_check=ecs.HealthCheck(command=["CMD-SHELL", "pgrep -f fluent-bit || exit 1"],
                                     interval=Duration.seconds(30),
                                     timeout=Duration.seconds(5), retries=3,
                                     start_period=Duration.seconds(30)),
        firelens_config=ecs.FirelensConfig(
            type=ecs.FirelensLogRouterType.FLUENTBIT,
            options=ecs.FirelensOptions(config_file_type=ecs.FirelensConfigFileType.FILE,
                                        config_file_value="/config/fluent-bit.conf",
                                        enable_ecs_log_metadata=False)))
    app = task_definition.add_container(
        "Container",
        image=ecs.ContainerImage.from_ecr_repository(repository, INFERENCE_SERVICE_TAG),
        cpu=2048, memory_reservation_mib=16000, essential=True,
        environment={"METRICS_NAMESPACE": "BasaltInference/BasaltInference",
                     "MODEL_ID": "Flint", "AWS_REGION": s.region, "STAGE": "dev",
                     "ENVIRONMENT": "dev", "MODEL_PATH": "/mnt/models/basalt-tensorrt-fp8",
                     "LOG_LEVEL": "INFO"},
        logging=ecs.FireLensLogDriver(options={}),
        port_mappings=[ecs.PortMapping(container_port=8080, host_port=8080,
                                       protocol=ecs.Protocol.TCP)],
        gpu_count=1)
    app.add_mount_points(ecs.MountPoint(source_volume="models-volume",
                                        container_path="/mnt/models", read_only=False))
    service = ecs.Ec2Service(s, "EcsService", cluster=app_cluster,
                             task_definition=task_definition,
                             service_name=f"{prefix}-inference", desired_count=0,
                             min_healthy_percent=0, max_healthy_percent=100)

    exports(
        s,
        DefaultClusterName=default_cluster.cluster_name,
        AppClusterName=app_cluster.cluster_name,
        TaskDefinitionArn=task_definition.task_definition_arn,
        ServiceName=service.service_name,
        LogGroupName=log_group.log_group_name,
        EcrRepositoryName=repository.repository_name,
        EcrRepositoryUri=repository.repository_uri,
        TaskRoleArn=task_role.role_arn,
        ExecutionRoleArn=execution.role_arn,
        VpcId=vpc.vpc_id,
    )


def deployment_controllers(s: cdk.Stack, *, prefix: str) -> None:
    """Two idle Fargate services behind one internal ALB: a rolling and a CodeDeploy one."""
    vpc = make_vpc(s, "EcsVpc", ("ecs-subnet", ISOLATED, 24), max_azs=3, nat_gateways=0)
    isolated = select(ISOLATED)
    service_sg = ec2.SecurityGroup(s, "EcsServiceSecurityGroup", vpc=vpc,
                                   description="Security group for ECS services",
                                   security_group_name=f"{prefix}-ecs-service-sg")
    service_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(80),
                                "Allow HTTP traffic from inside the VPC")
    alb_sg = ec2.SecurityGroup(s, "AlbSecurityGroup", vpc=vpc,
                               description="Security group for Application Load Balancer",
                               security_group_name=f"{prefix}-alb-sg")
    for port in (80, 8080):
        alb_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(port),
                                f"Allow HTTP on {port} from inside the VPC")
    cluster = ecs.Cluster(s, "FargateCluster", cluster_name=f"{prefix}-fargate-cluster",
                          vpc=vpc, enable_fargate_capacity_providers=True)
    execution = iam.Role(s, "TaskExecutionRole",
                         assumed_by=_service("ecs-tasks"),
                         managed_policies=[_managed(
                             _EXECUTION_POLICY)])
    task_role = iam.Role(s, "TaskRole", assumed_by=_service("ecs-tasks"))

    def task_definition(logical, family, stream):
        definition = ecs.FargateTaskDefinition(s, logical, family=f"{prefix}-{family}",
                                               cpu=256, memory_limit_mib=512,
                                               execution_role=execution, task_role=task_role)
        definition.add_container(
            "app", container_name="app",
            image=ecs.ContainerImage.from_registry("public.ecr.aws/docker/library/nginx:1.30"),
            port_mappings=[ecs.PortMapping(container_port=80, protocol=ecs.Protocol.TCP)],
            logging=ecs.LogDrivers.aws_logs(stream_prefix=stream,
                                            log_retention=logs.RetentionDays.ONE_WEEK))
        return definition

    rolling_td = task_definition("RollingTaskDefinition", "quartz-ecs-rolling", "rolling-service")
    blue_green_td = task_definition("BlueGreenTaskDefinition", "quartz-ecs-blue-green",
                                    "blue-green-service")
    alb = elbv2.ApplicationLoadBalancer(s, "ApplicationLoadBalancer",
                                        load_balancer_name=f"{prefix}-ecsalb", vpc=vpc,
                                        internet_facing=False, security_group=alb_sg,
                                        vpc_subnets=isolated)

    def target_group(logical, name):
        return elbv2.ApplicationTargetGroup(
            s, logical, target_group_name=f"{prefix}-{name}", vpc=vpc, port=80,
            protocol=elbv2.ApplicationProtocol.HTTP, target_type=elbv2.TargetType.IP,
            health_check=elbv2.HealthCheck(enabled=True, path="/",
                                           protocol=elbv2.Protocol.HTTP))

    rolling_tg = target_group("RollingTargetGroup", "rolltg")
    blue_green_tg = target_group("BlueGreenTargetGroup", "bgtg2")
    alb.add_listener("RollingListener", port=80, protocol=elbv2.ApplicationProtocol.HTTP,
                     open=False,
                     default_target_groups=[rolling_tg])
    alb.add_listener("BlueGreenListener", port=8080, protocol=elbv2.ApplicationProtocol.HTTP,
                     open=False,
                     default_target_groups=[blue_green_tg])

    def service(logical, name, definition, controller, platform, group, configuration):
        created = ecs.FargateService(
            s, logical, service_name=f"{prefix}-{name}", cluster=cluster,
            task_definition=definition, desired_count=0, assign_public_ip=False,
            security_groups=[service_sg], vpc_subnets=isolated,
            deployment_controller=ecs.DeploymentController(type=controller),
            platform_version=platform, enable_execute_command=True,
            health_check_grace_period=Duration.seconds(0))
        created.attach_to_application_target_group(group)
        created.node.default_child.deployment_configuration = configuration
        return created

    rolling = service(
        "RollingService", "quartz-ecs-rolling", rolling_td, ecs.DeploymentControllerType.ECS,
        ecs.FargatePlatformVersion.LATEST, rolling_tg,
        ecs.CfnService.DeploymentConfigurationProperty(
            maximum_percent=200, minimum_healthy_percent=100,
            deployment_circuit_breaker=ecs.CfnService.DeploymentCircuitBreakerProperty(
                enable=False, rollback=False)))
    blue_green = service(
        "BlueGreenService", "quartz-ecs-blue-green", blue_green_td,
        ecs.DeploymentControllerType.CODE_DEPLOY, ecs.FargatePlatformVersion.VERSION1_4,
        blue_green_tg,
        ecs.CfnService.DeploymentConfigurationProperty(maximum_percent=200,
                                                       minimum_healthy_percent=100))

    exports(
        s,
        ClusterName=cluster.cluster_name,
        ClusterArn=cluster.cluster_arn,
        RollingServiceName=rolling.service_name,
        RollingServiceArn=rolling.service_arn,
        RollingTaskDefinitionArn=rolling_td.task_definition_arn,
        BlueGreenServiceName=blue_green.service_name,
        BlueGreenServiceArn=blue_green.service_arn,
        BlueGreenTaskDefinitionArn=blue_green_td.task_definition_arn,
        RollingTargetGroupArn=rolling_tg.target_group_arn,
        BlueGreenTargetGroupArn=blue_green_tg.target_group_arn,
        VpcId=vpc.vpc_id,
        SecurityGroupId=service_sg.security_group_id,
        AlbArn=alb.load_balancer_arn,
        AlbDnsName=alb.load_balancer_dns_name,
    )


def scheduled_task(s: cdk.Stack, *, prefix: str) -> None:
    """A monthly EventBridge rule that runs a Fargate task in private subnets."""
    bucket = secure_bucket(s, "DeploymentBucket", bucket_name=f"{prefix}-scheduled-deploy")
    log_group = logs.LogGroup(s, "QuartzTaskLogGroup",
                              log_group_name=f"{prefix}-QuartzService-ScheduledTaskLogGroup",
                              log_group_class=logs.LogGroupClass.STANDARD,
                              removal_policy=DESTROY)
    # The task pulls a public image, so its private subnets egress through a NAT gateway.
    vpc = make_vpc(s, "TaskVpc", ("Public", PUBLIC, 24), ("Private", PRIVATE, 24),
                   vpc_name=f"{prefix}-scheduled-vpc", max_azs=2, nat_gateways=1)
    group = ec2.SecurityGroup(s, "TaskSecurityGroup", vpc=vpc,
                              description="Security group for ECS Fargate tasks")
    run_role = _role(s, "ScheduledTaskRunRole", f"{prefix}-scheduled-task-run",
                     "ecs-tasks.amazonaws.com", _EXECUTION_POLICY)
    bucket.grant_read(run_role)
    log_group.grant_write(run_role)
    events_role = iam.Role(s, "EventBridgeRole", role_name=f"{prefix}-scheduled-events",
                           assumed_by=_service("events"),
                           max_session_duration=Duration.hours(1))
    events_role.add_to_policy(iam.PolicyStatement(actions=["ecs:RunTask"], resources=["*"]))
    events_role.add_to_policy(iam.PolicyStatement(actions=["iam:PassRole"],
                                                  resources=[run_role.role_arn]))
    cluster = ecs.Cluster(s, "ScheduledTaskCluster",
                          cluster_name=f"{prefix}-QuartzService-Default", vpc=vpc,
                          enable_fargate_capacity_providers=True)
    task_definition = ecs.FargateTaskDefinition(
        s, "QuartzTaskDefinition", family=f"{prefix}-QuartzServiceScheduledTask",
        cpu=1024, memory_limit_mib=2048, task_role=run_role, execution_role=run_role,
        runtime_platform=ecs.RuntimePlatform(
            cpu_architecture=ecs.CpuArchitecture.ARM64,
            operating_system_family=ecs.OperatingSystemFamily.LINUX))
    # An artifact location in a bucket this account does not own.
    artifact = ("s3://deploymentbucket-12345a4solks4a7cab4205857a8c7r06796aa66a/"
                "pipelines_aggregate_transform_1234579/"
                "a12r5a11-cswd-1234-8a0a-ab5c2f2fc721_aaa0eae2a1ad7b1b5bbdff/artifact")
    task_definition.add_container(
        "CodeTestContainer", container_name="CodeTestContainer",
        image=ecs.ContainerImage.from_registry("public.ecr.aws/amazonlinux/amazonlinux:latest"),
        essential=True,
        environment={
            "SCHEMA_TYPE": "Generic", "TEST_SELECTOR": "scheduled.*Test", "RUNTIME": "python3",
            "EXECUTION_COMMAND": "testPlatform/runTests.sh", "HANDLER": "FargateHandler",
            "FARGATE_RUN_LOG_GROUP": "/aws/fargate/scheduled-tests",
            "FARGATE_RUN_LOG_STREAM_NAME": "scheduled-tests",
            "CANARY_TESTS_REGION": s.region, "CANARY_TESTS_IS_PROD": "true",
            "CANARY_ACCOUNT_ID": s.account, "S3_LOCATION": artifact,
            "DOWNLOAD_TO": "/download/scheduled-test",
            "EXTRACT_TO": "/workspace/scheduled-test",
            "FARGATE_RUN_WORKSPACE_DIR": "/workspace/scheduled-test",
            "TIMEOUT": "54000000000", "FARGATE_RUN_TIMEOUT_VALUE": "54000000000",
            "CUSTOM_BOOTSTRAP_COMMAND": ('echo "No pre-run setup command or script provided. '
                                         'Skipping the pre-run setup phase."'),
            "ECS_CONTAINER_STOP_TIMEOUT": "300", "FARGATE_PLATFORM_VERSION": "LATEST",
            "REPORT_TEST_ARTIFACTS": "false", "TOOL_OPTIONS": "",
        },
        logging=ecs.LogDrivers.aws_logs(log_group=log_group, stream_prefix="scheduled-tests"))
    rule = events.Rule(s, "MonthlyQuartzRule",
                       rule_name=f"{prefix}-QuartzService-MonthlyScheduledRule",
                       description="Monthly EventBridge rule to trigger scheduled ECS task",
                       schedule=events.Schedule.expression("cron(05 23 27 * ? *)"),
                       enabled=True)
    rule.add_target(targets.EcsTask(
        cluster=cluster, task_definition=task_definition, role=events_role,
        launch_type=ecs.LaunchType.FARGATE,
        platform_version=ecs.FargatePlatformVersion.LATEST,
        subnet_selection=select(PRIVATE),
        security_groups=[group], assign_public_ip=False))

    exports(
        s,
        DeploymentBucketName=bucket.bucket_name,
        QuartzTaskLogGroupName=log_group.log_group_name,
        EcsClusterName=cluster.cluster_name,
        EcsClusterArn=cluster.cluster_arn,
        TaskDefinitionArn=task_definition.task_definition_arn,
        EventBridgeRuleName=rule.rule_name,
    )


#: What the processing function raises on every invocation.
VALIDATION_ERROR = "Configuration validation failed: missing required field 'targetBucket'"
#: CloudFormation logical ids the function's environment holds in place of AppConfig ids.
APPCONFIG_LOGICAL_IDS = {
    "APP_CONFIG_APPLICATION": "GRNCMSAppConfigApplication537888D7",
    "APP_CONFIG_CONFIGURATION": "GRNCMSAppConfigConfigurationConfigurationProfile7AB3584E",
    "APP_CONFIG_ENVIRONMENT": "GRNCMSAppConfigEnvironment9802B737",
}
#: The hosted configuration the profile deploys.
APPCONFIG_CONTENT = {"useNewBackend": True}

_FAILING_HANDLER = f"""
def handler(event, context):
    raise RuntimeError({VALIDATION_ERROR!r})
"""

_CONFIG_READER = """
import json
import os

import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    print('Event:', json.dumps(event))
    ids = {k: os.environ[f'APP_CONFIG_{k.upper()}']
           for k in ('application', 'environment', 'configuration')}
    print('AppConfig IDs:', json.dumps(ids))
    try:
        boto3.client('appconfig').get_configuration(
            Application=ids['application'], Environment=ids['environment'],
            Configuration=ids['configuration'], ClientId='lambda-client')
        print('AppConfig retrieved successfully')
    except ClientError as error:
        print('Failed to retrieve AppConfig:', error.response['Error']['Code'])
        print('Falling back to default: useNewBackend = false')
    return {'statusCode': 200, 'body': json.dumps({'message': 'Function executed'})}
"""


def failing_state_machine(s: cdk.Stack, *, prefix: str) -> None:
    """A standard state machine whose only task invokes a function that always raises."""
    log_group = logs.LogGroup(s, "ProcessingLambdaLogGroup", removal_policy=DESTROY)
    fn = lambda_.Function(s, "ProcessingLambda", log_group=log_group,
                          function_name=f"{prefix}-Processing",
                          runtime=lambda_.Runtime.PYTHON_3_12, handler="index.handler",
                          code=lambda_.Code.from_inline(_FAILING_HANDLER))
    role = iam.Role(s, "StateMachineRole", assumed_by=_service("states"))
    fn.grant_invoke(role)
    machine = sfn.StateMachine(
        s, "QuartzConfigurationStateMachine",
        state_machine_name=f"{prefix}-QuartzConfiguration",
        definition_body=sfn.DefinitionBody.from_chainable(tasks.LambdaInvoke(
            s, "InvokeProcessingLambda", lambda_function=fn,
            retry_on_service_exceptions=False)),
        role=role, state_machine_type=sfn.StateMachineType.STANDARD)
    exports(
        s,
        StateMachineArn=machine.state_machine_arn,
        ProcessingLambdaArn=fn.function_arn,
        ProcessingLambdaName=fn.function_name,
    )


def config_function(s: cdk.Stack, *, prefix: str) -> None:
    """An AppConfig profile deployed all at once, and a function whose environment names the
    profile by CloudFormation logical ids, so its lookups miss and it falls back."""
    application = appconfig.Application(
        s, "GRNCMSAppConfigApplication537888D7",
        application_name=f"{prefix}-GarnetAppConfig",
        description="Configuration for Garnet application")
    environment = appconfig.Environment(
        s, "GRNCMSAppConfigEnvironment9802B737", application=application,
        environment_name="beta", description="beta environment for GarnetAppConfig",
        deletion_protection_check=appconfig.DeletionProtectionCheck.BYPASS)
    strategy = appconfig.DeploymentStrategy(
        s, "FastDeploymentStrategy", deployment_strategy_name=f"{prefix}-AllAtOnceNoBake",
        rollout_strategy=appconfig.RolloutStrategy.linear(
            growth_factor=100, deployment_duration=Duration.minutes(0),
            final_bake_time=Duration.minutes(0)))
    hosted = appconfig.HostedConfiguration(
        s, "GRNCMSAppConfigConfigurationConfigurationProfile7AB3584E",
        application=application,
        content=appconfig.ConfigurationContent.from_inline_json(
            json.dumps(APPCONFIG_CONTENT)),
        name="GarnetServicebeta-GRNCMSAppConfigConfiguration-EE839D38",
        type=appconfig.ConfigurationType.FREEFORM, deploy_to=[environment],
        deployment_strategy=strategy,
        # Reading the profile marks it recently used; the stack delete must not wait it out.
        deletion_protection_check=appconfig.DeletionProtectionCheck.BYPASS)

    def table(logical, name, partition, sort=None):
        return dynamodb.Table(
            s, logical, table_name=f"{prefix}-{name}",
            partition_key=dynamodb.Attribute(name=partition,
                                             type=dynamodb.AttributeType.STRING),
            sort_key=(dynamodb.Attribute(name=sort, type=dynamodb.AttributeType.STRING)
                      if sort else None),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True))

    annotation = table("AnnotationStagingTable", "Garnet-AnnotationStaging", "contentId",
                       "marketplaceId_shoppableStrategy")
    media = table("MediaDetailsTable", "GRN-MEDIA-DETAILS", "contentId", "marketplaceId")
    scene_info = table("SceneInfoV3Table", "SCENE-INFO-V3", "physicalId", "marketplaceIdStrategyId")
    scene_tags = table("SceneTagInfoTable", "SCENE-TAG-INFO", "tagId")

    def role(logical, name, description):
        return iam.Role(s, logical, role_name=f"{prefix}-{name}",
                        assumed_by=_service("lambda"),
                        description=description)

    cms = role("CMSCrossAccountRole", "garnet-cms-cross-account",
               "Cross-account access to AnnotationStaging and AssetMetadata tables")
    annotation.grant_read_write_data(cms)
    shoppable = role("CobaltShoppableCrossAccountRole", "cobalt-scenes-cross-account",
                     "Cross-account access to SceneInfoV3 and MediaDetails tables")
    scene_info.grant_read_data(shoppable)
    media.grant_read_data(shoppable)
    cobalt = role("CobaltCrossAccountRole", "cobalt-cross-account",
                  "Cross-account access to SceneTagInfo table")
    scene_tags.grant_read_data(cobalt)
    s3_access = role("S3AccessRole", "garnet-s3-access",
                     "Cross-account S3 access for generating presigned URLs")
    s3_access.add_to_policy(iam.PolicyStatement(actions=["s3:GetObject", "s3:PutObject"],
                                                resources=["arn:aws:s3:::*/*"]))

    log_group = logs.LogGroup(s, "GetShoppableMediaFunctionLogGroup", removal_policy=DESTROY)
    fn = lambda_.Function(
        s, "GetShoppableMediaFunction", log_group=log_group,
        function_name=f"{prefix}-getShoppableMediaByID",
        runtime=lambda_.Runtime.PYTHON_3_12, handler="index.handler",
        code=lambda_.Code.from_inline(_CONFIG_READER), memory_size=512,
        timeout=Duration.seconds(180),
        environment={
            **APPCONFIG_LOGICAL_IDS,
            "CMS_CROSS_ACCOUNT_ROLE_ARN": cms.role_arn,
            "JASPER_CROSS_ACCOUNT_ROLE_ARN": cobalt.role_arn,
            "JASPER_SHOPPABLE_CROSS_ACCOUNT_ROLE_ARN": shoppable.role_arn,
            "S3_ACCESS_ROLE_ARN": s3_access.role_arn,
            "STAGE": "beta",
        })
    fn.add_to_role_policy(iam.PolicyStatement(
        actions=["appconfig:GetConfiguration", "appconfig:GetLatestConfiguration",
                 "appconfig:StartConfigurationSession"],
        resources=["*"]))
    fn.add_to_role_policy(iam.PolicyStatement(
        actions=["sts:AssumeRole"],
        resources=[r.role_arn for r in (cms, cobalt, shoppable, s3_access)]))
    annotation.grant_read_write_data(fn)
    for t in (media, scene_info, scene_tags):
        t.grant_read_data(fn)

    exports(
        s,
        AppConfigApplicationId=application.application_id,
        AppConfigEnvironmentId=environment.environment_id,
        AppConfigConfigurationProfileId=hosted.configuration_profile_id,
        LambdaFunctionName=fn.function_name,
        AnnotationStagingTableName=annotation.table_name,
        MediaDetailsTableName=media.table_name,
        SceneInfoV3TableName=scene_info.table_name,
        SceneTagInfoTableName=scene_tags.table_name,
    )


def ssm_documents(s: cdk.Stack, *, prefix: str) -> None:
    """Command documents for a host service, a session document and the role that runs them."""
    log_group = logs.LogGroup(s, "CedarSSMLogGroup",
                              log_group_name=f"/{prefix}/BirchCedar/Maple52/Prod/ssm.log",
                              retention=logs.RetentionDays.ONE_MONTH,
                              removal_policy=DESTROY)
    role = iam.Role(s, "BirchServiceRole", role_name=f"{prefix}-birch-service",
                    assumed_by=_service("ssm"),
                    description="IAM role for BirchService SSM operations")
    document_prefix = f"{prefix}-BirchService-"
    documents_arn = (f"arn:{s.partition}:ssm:{s.region}:{s.account}:document/"
                     f"{document_prefix}*")
    instances_arn = f"arn:{s.partition}:ec2:{s.region}:{s.account}:instance/*"
    iam.Policy(s, "BirchServiceRoleDefaultPolicy",
               policy_name=f"{prefix}-birch-service-default",
               statements=[
                   iam.PolicyStatement(actions=[
                       "ssm:DescribeDocument", "ssm:DescribeDocumentParameters",
                       "ssm:DescribeDocumentPermission", "ssm:GetCommandInvocation",
                       "ssm:GetDocument", "ssm:ListCommandInvocations", "ssm:ListCommands",
                       "ssm:ListDocuments"], resources=["*"]),
                   iam.PolicyStatement(actions=["ssm:SendCommand"],
                                       resources=[instances_arn, documents_arn]),
               ]).attach_to_role(role)

    allowed = "^[^;\\\\<>*`&$!#]*$"

    def command(logical, command_name, step, script, run, parameter=None,
                update_method=None):
        parameters = {}
        if parameter:
            name, description = parameter
            parameters[name] = {"type": "String", "description": description,
                                "allowedPattern": allowed}
        ssm.CfnDocument(
            s, logical, name=f"{document_prefix}{command_name}", document_type="Command",
            update_method=update_method,
            content={"schemaVersion": "2.2", "description": f"{script} $@",
                     "parameters": parameters,
                     "mainSteps": [{"name": step, "action": "aws:runShellScript",
                                    "inputs": {"runCommand": [run]}}]},
            tags=[cdk.CfnTag(key="Service", value="BirchService"),
                  cdk.CfnTag(key="Command", value=command_name)])

    birch = "/usr/local/ec2/birch/birch-service"
    command("BirchClearCounters", "clear-counters", "clearcounters",
            f"{birch} clear-counters", f"{birch} clear-counters ")
    for logical, name, step in (("BirchStopTraffic", "traffic-stop", "trafficstop"),
                                ("BirchStartTraffic", "traffic-start", "trafficstart"),
                                ("BirchSetHostname", "set-hostname", "sethostname")):
        command(logical, name, step, f"{birch} {name}", f"{birch} {name} {{{{ args }}}}",
                ("args", f"(Required) args for {name}"))
    command("BirchSetRole", "set-role", "setrole", "/usr/local/ec2/birch/set-role",
            "/usr/local/ec2/birch/set-role '{{ roleDataJson }}'",
            ("roleDataJson",
             "(Required) The role data in json form as previously sent to the service API."),
            update_method="NewVersion")
    ssm.CfnDocument(
        s, "CedarSSMAuditLog", name=f"{prefix}-SessionManagerRunShell",
        document_type="Session", update_method="NewVersion",
        content={"schemaVersion": "1.0",
                 "description": "Enable session manager audit log to Cloudwatch",
                 "sessionType": "Standard_Stream",
                 "inputs": {"cloudWatchEncryptionEnabled": False,
                            "s3EncryptionEnabled": False, "runAsDefaultUser": "",
                            "cloudWatchStreamingEnabled": False, "runAsEnabled": False,
                            "cloudWatchLogGroupName": log_group.log_group_name}},
        tags=[cdk.CfnTag(key="Service", value="BirchCedar"),
              cdk.CfnTag(key="Purpose", value="SSM-Audit")])

    exports(
        s,
        BirchServiceRoleName=role.role_name,
        SSMLogGroupName=log_group.log_group_name,
        SendCommandEC2Resource=instances_arn,
        SendCommandDocumentResource=documents_arn,
        DocumentPrefix=document_prefix,
    )


#: ``part: the function that populates its stack``, in deployment order; the region of each
#: comes from context.
STACKS = {
    "AppRoles": app_roles,
    "AliasFunctions": alias_functions,
    "FlowLogVpc": flow_log_vpc,
    "LegacyAmiInstance": legacy_ami_instance,
    "PrivateNatServer": private_nat_server,
    "TransitFirewall": transit_firewall,
    "HelperAsg": helper_asg,
    "DualVpcHelper": dual_vpc_helper,
    "DisabledKeyAsg": disabled_key_asg,
    "FargateWebApp": fargate_web_app,
    "CacheTransit": cache_transit,
    "FirelensService": firelens_service,
    "CrashLoopService": crash_loop_service,
    "ClusterNlb": cluster_nlb,
    "SparkCluster": spark_cluster,
    "ScheduledTask": scheduled_task,
    "RoleReportJob": role_report_job,
    "FailingStateMachine": failing_state_machine,
    "LakeFormationSettings": lake_formation_settings,
    "LakeFormationEtl": lake_formation_etl,
    "RedshiftClusters": redshift_clusters,
    "HyperPodNlb": hyper_pod_nlb,
    "CrossAccountImage": cross_account_image,
    "MetadataTags": metadata_tags,
    "ClickstreamData": clickstream_data,
    "PrivateLoadBalancers": private_load_balancers,
    "GpuInference": gpu_inference,
    "SecondaryEniAsg": secondary_eni_asg,
    "DeploymentControllers": deployment_controllers,
    "AuroraPostgres": aurora_postgres,
    "ConfigFunction": config_function,
    "SsmDocuments": ssm_documents,
}


def _pairs(value: str) -> dict[str, str]:
    """``{key: value}`` from a ``"<key>=<value>;..."`` context string."""
    return dict(item.split("=", 1) for item in value.split(";") if "=" in item)


def regions(value: str) -> dict[str, str]:
    """``{part: region}`` from the ``regions`` context; every stack must be placed."""
    parsed = _pairs(value)
    missing = [part for part in STACKS if not parsed.get(part)]
    if missing:
        raise ValueError(f"the regions context places no region for {missing}")
    return {part: parsed[part] for part in STACKS}


def zones(value: str, wanted: set[str]) -> dict[str, list[str]]:
    """``{region: zones}`` from the ``azs`` context; every region of the estate must be named."""
    parsed = _pairs(value)
    missing = sorted(r for r in wanted if not parsed.get(r))
    if missing:
        raise ValueError(f"the azs context names no zones for {missing}")
    return {region: parsed[region].split(",") for region in sorted(wanted)}


def build(app: cdk.App, placed: dict[str, str], azs: dict[str, list[str]]) -> None:
    """Every stack of the estate; the Lake Formation governed job waits for the settings."""
    ctx = app.node.try_get_context
    account, prefix, qualifier = ctx("account"), ctx("prefix"), ctx("qualifier")
    extra = {
        "LakeFormationSettings": {"qualifier": qualifier, "lf_admin_arn": ctx("lf-admin-arn")},
        "ClusterNlb": {"s3_prefix_list": ctx("s3-prefix-list")},
        "PrivateNatServer": {"zone": azs[placed["PrivateNatServer"]][1]},
        "RoleReportJob": {"home_region": placed["AppRoles"]},
    }
    stacks = {}
    for part, populate in STACKS.items():
        kwargs = extra.get(part, {})
        if part != "LakeFormationSettings":
            kwargs = {"prefix": prefix, **kwargs}
        stacks[part] = cdk.Stack(
            app, f"{prefix}-{part}",
            env=cdk.Environment(account=account, region=placed[part]),
            synthesizer=cdk.DefaultStackSynthesizer(qualifier=qualifier))
        populate(stacks[part], **kwargs)
    stacks["LakeFormationEtl"].add_dependency(stacks["LakeFormationSettings"])


app = cdk.App()
PLACED = regions(app.node.try_get_context("regions") or "")
AZS = zones(app.node.try_get_context("azs") or "", set(PLACED.values()))
# Each region's zone lookup is answered from context, so synth makes no AWS call.
for region, region_zones in AZS.items():
    app.node.set_context(
        f"availability-zones:account={app.node.try_get_context('account')}:region={region}",
        region_zones,
    )
build(app, PLACED, AZS)
app.synth()
