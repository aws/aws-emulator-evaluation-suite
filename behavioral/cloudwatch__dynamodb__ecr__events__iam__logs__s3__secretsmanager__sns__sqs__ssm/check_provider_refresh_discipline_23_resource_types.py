"""provider-refresh-discipline-23-resource-types."""

from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provider-refresh-discipline-23-resource-types"

GROUP = "representation-consistency"

SERVICES = [
    "cloudwatch",
    "dynamodb",
    "ecr",
    "events",
    "iam",
    "logs",
    "s3",
    "secretsmanager",
    "sns",
    "sqs",
    "ssm",
]

_ROW_COUNT = 23

# Paths that legitimately move between two consecutive describes of an UNTOUCHED resource, measured
# on real AWS (two describes 20 s apart, all 23 types): only the CloudWatch
# alarm's evaluation fields and SNS's subscription counters drift. Naming them explicitly rather
# than wildcarding is the difference between a check that is exact and one that is vacuous.
_VOLATILE: dict[str, set[str]] = {
    "cloudwatch_metric_alarm": {
        "StateReason",
        "StateReasonData",
        "StateTransitionedTimestamp",
        "StateUpdatedTimestamp",
        "StateValue",
    },
    # A composite alarm's rule references the metric alarm above, so it inherits that alarm's
    # INSUFFICIENT_DATA -> OK transition. Measured stable in a 20 s window; excluded because the
    # transition is real and time-driven, not a representation defect.
    "cloudwatch_composite_alarm": {
        "StateReason",
        "StateReasonData",
        "StateTransitionedTimestamp",
        "StateUpdatedTimestamp",
        "StateValue",
    },
    # Counters, not attributes the caller set; they move because the sns_subscription row below
    # subscribes to this very topic.
    "sns_topic": {
        "Attributes.SubscriptionsConfirmed",
        "Attributes.SubscriptionsPending",
        "Attributes.SubscriptionsDeleted",
    },
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """For 23 resource types, every attribute the caller set reads back with the same value and type,
    the create response and the first describe agree on shared fields, and two consecutive describes
    are identical outside a named volatile set: the Terraform provider's refresh invariants."""
    ctx.verify_account_safety()
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    ddb = ctx.client("dynamodb")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    ssm = ctx.client("ssm")
    sm = ctx.client("secretsmanager")
    ev = ctx.client("events")
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")

    p = ctx.unique_name("sim2real-xsvc-e3rd-")
    acct = ctx.client("sts").get_caller_identity()["Account"]
    bucket = f"{p}-b"
    obj_key = "obj/probe.txt"
    topic_arn = f"arn:aws:sns:{ctx.region}:{acct}:{p}-topic"
    policy_arn = f"arn:aws:iam::{acct}:policy/{p}-pol"
    param = f"/sim2real/e3rd/{p}/p"
    table = f"{p}-tbl"
    log_group = f"/sim2real/e3rd/{p}"
    state: dict[str, Any] = {}

    # The bucket itself is not one of the 23 rows: it is the container the seven s3 rows configure.
    s3.create_bucket(
        Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realE3",
                "Effect": "Allow",
                "Principal": {"AWS": acct},
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/obj/*"],
            }
        ],
    }
    bucket_policy_v2 = json.loads(json.dumps(bucket_policy))
    bucket_policy_v2["Statement"][0]["Sid"] = "sim2realE3v2"
    # AWS expands a bare account id to the root ARN and collapses single-element Action/Resource
    # lists to scalars. Both are MEASURED normalisations, so the expected value is the normalised
    # form -- an endpoint echoing back exactly what was sent fails here, correctly.
    bucket_policy_read = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realE3",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/obj/*",
            }
        ],
    }

    dash_body = {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": "sim2real-e3"},
            }
        ]
    }
    dash_body_v2 = json.loads(json.dumps(dash_body))
    dash_body_v2["widgets"][0]["properties"]["markdown"] = "sim2real-e3-v2"

    def ecr_policy(count: int) -> dict:
        return {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "sim2real e3",
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "sinceImagePushed",
                        "countUnit": "days",
                        "countNumber": count,
                    },
                    "action": {"type": "expire"},
                }
            ]
        }

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    def alarm(threshold: float) -> dict:
        return dict(
            AlarmName=f"{p}-alarm",
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=3,
            DatapointsToAlarm=2,
            MetricName=f"{p}-e",
            Namespace="sim2real/e3rd",
            Period=60,
            Statistic="Sum",
            Threshold=threshold,
            TreatMissingData="notBreaching",
        )

    def metric_filter(default_value: float) -> dict:
        return dict(
            logGroupName=log_group,
            filterName=f"{p}-mf",
            filterPattern='{ $.level = "ERROR" }',
            metricTransformations=[
                {
                    "metricName": f"{p}-e",
                    "metricNamespace": "sim2real/e3rd",
                    "metricValue": "1",
                    "defaultValue": default_value,
                    "unit": "Count",
                }
            ],
        )

    # ---------------------------------------------------------------------------------- the table
    # (name, create, describe, set_fields, json_paths, mutate, settled, expect_changed, absent,
    #  delete) -- one row per resource type, in dependency order. Deletes run in reverse.
    rows: list[dict] = [
        dict(
            name="s3_bucket_policy",
            create=lambda: s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy)),
            describe=lambda: s3.get_bucket_policy(Bucket=bucket),
            set_fields={"Policy": bucket_policy_read},
            json_paths={"Policy"},
            mutate=lambda: s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy_v2)),
            settled=lambda f: json.loads(f["Policy"])["Statement"][0]["Sid"] == "sim2realE3v2",
            expect_changed={"Policy"},
            absent=("code", ("NoSuchBucketPolicy", "The bucket policy does not exist")),
            delete=lambda: s3.delete_bucket_policy(Bucket=bucket),
        ),
        dict(
            name="s3_bucket_sse",
            create=lambda: s3.put_bucket_encryption(
                Bucket=bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                            "BucketKeyEnabled": True,
                        }
                    ]
                },
            ),
            describe=lambda: s3.get_bucket_encryption(Bucket=bucket),
            set_fields={
                "ServerSideEncryptionConfiguration.Rules.0."
                "ApplyServerSideEncryptionByDefault.SSEAlgorithm": "AES256",
                "ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled": True,
            },
            json_paths=set(),
            mutate=lambda: s3.put_bucket_encryption(
                Bucket=bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                            "BucketKeyEnabled": False,
                        }
                    ]
                },
            ),
            settled=lambda f: f["ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled"]
            is False,
            expect_changed={"ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled"},
            # MEASURED: DeleteBucketEncryption does NOT make the config absent -- AWS reverts the
            # bucket to the SSE-S3 default, which is a documented behaviour an endpoint returning an
            # empty configuration would fail.
            absent=(
                "default",
                {
                    "ServerSideEncryptionConfiguration.Rules.0."
                    "ApplyServerSideEncryptionByDefault.SSEAlgorithm": "AES256",
                    "ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled": False,
                },
            ),
            delete=lambda: s3.delete_bucket_encryption(Bucket=bucket),
        ),
        dict(
            name="s3_public_access_block",
            create=lambda: s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            ),
            describe=lambda: s3.get_public_access_block(Bucket=bucket),
            set_fields={
                "PublicAccessBlockConfiguration.BlockPublicAcls": True,
                "PublicAccessBlockConfiguration.IgnorePublicAcls": False,
                "PublicAccessBlockConfiguration.BlockPublicPolicy": True,
                "PublicAccessBlockConfiguration.RestrictPublicBuckets": True,
            },
            json_paths=set(),
            mutate=lambda: s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            ),
            settled=lambda f: f["PublicAccessBlockConfiguration.IgnorePublicAcls"] is True,
            expect_changed={"PublicAccessBlockConfiguration.IgnorePublicAcls"},
            absent=(
                "code",
                (
                    "NoSuchPublicAccessBlockConfiguration",
                    "The public access block configuration was not found",
                ),
            ),
            delete=lambda: s3.delete_public_access_block(Bucket=bucket),
        ),
        dict(
            name="s3_bucket_lifecycle",
            create=lambda: s3.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={
                    "Rules": [
                        {
                            "ID": "sim2real-expire",
                            "Status": "Enabled",
                            "Filter": {"Prefix": "e3/"},
                            "Expiration": {"Days": 17},
                        }
                    ]
                },
            ),
            describe=lambda: s3.get_bucket_lifecycle_configuration(Bucket=bucket),
            set_fields={
                "Rules.0.ID": "sim2real-expire",
                "Rules.0.Status": "Enabled",
                "Rules.0.Filter.Prefix": "e3/",
                "Rules.0.Expiration.Days": 17,
            },
            json_paths=set(),
            mutate=lambda: s3.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={
                    "Rules": [
                        {
                            "ID": "sim2real-expire",
                            "Status": "Enabled",
                            "Filter": {"Prefix": "e3/"},
                            "Expiration": {"Days": 23},
                        }
                    ]
                },
            ),
            settled=lambda f: f["Rules.0.Expiration.Days"] == 23,
            expect_changed={"Rules.0.Expiration.Days"},
            absent=(
                "code",
                ("NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist"),
            ),
            delete=lambda: s3.delete_bucket_lifecycle(Bucket=bucket),
        ),
        dict(
            name="s3_bucket_cors",
            create=lambda: s3.put_bucket_cors(
                Bucket=bucket,
                CORSConfiguration={
                    "CORSRules": [
                        {
                            "AllowedMethods": ["GET"],
                            "AllowedOrigins": ["https://sim2real.invalid"],
                            "MaxAgeSeconds": 3017,
                        }
                    ]
                },
            ),
            describe=lambda: s3.get_bucket_cors(Bucket=bucket),
            set_fields={
                "CORSRules.0.AllowedMethods.0": "GET",
                "CORSRules.0.AllowedOrigins.0": "https://sim2real.invalid",
                "CORSRules.0.MaxAgeSeconds": 3017,
            },
            json_paths=set(),
            mutate=lambda: s3.put_bucket_cors(
                Bucket=bucket,
                CORSConfiguration={
                    "CORSRules": [
                        {
                            "AllowedMethods": ["GET"],
                            "AllowedOrigins": ["https://sim2real.invalid"],
                            "MaxAgeSeconds": 4017,
                        }
                    ]
                },
            ),
            settled=lambda f: f["CORSRules.0.MaxAgeSeconds"] == 4017,
            expect_changed={"CORSRules.0.MaxAgeSeconds"},
            absent=("code", ("NoSuchCORSConfiguration", "The CORS configuration does not exist")),
            delete=lambda: s3.delete_bucket_cors(Bucket=bucket),
        ),
        dict(
            name="s3_bucket_ownership_controls",
            create=lambda: s3.put_bucket_ownership_controls(
                Bucket=bucket,
                OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]},
            ),
            describe=lambda: s3.get_bucket_ownership_controls(Bucket=bucket),
            set_fields={"OwnershipControls.Rules.0.ObjectOwnership": "ObjectWriter"},
            json_paths=set(),
            mutate=lambda: s3.put_bucket_ownership_controls(
                Bucket=bucket,
                OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]},
            ),
            settled=lambda f: f["OwnershipControls.Rules.0.ObjectOwnership"]
            == "BucketOwnerPreferred",
            expect_changed={"OwnershipControls.Rules.0.ObjectOwnership"},
            absent=(
                "code",
                ("OwnershipControlsNotFoundError", "The bucket ownership controls were not found"),
            ),
            delete=lambda: s3.delete_bucket_ownership_controls(Bucket=bucket),
        ),
        dict(
            name="s3_object",
            create=lambda: s3.put_object(
                Bucket=bucket,
                Key=obj_key,
                Body=b"sim2real-e3-probe",
                ContentType="application/x-sim2real",
            ),
            describe=lambda: s3.head_object(Bucket=bucket, Key=obj_key),
            set_fields={"ContentType": "application/x-sim2real", "ContentLength": 17},
            json_paths=set(),
            mutate=lambda: s3.put_object(
                Bucket=bucket,
                Key=obj_key,
                Body=b"sim2real-e3-probe",
                ContentType="application/x-sim2real-v2",
            ),
            settled=lambda f: f["ContentType"] == "application/x-sim2real-v2",
            expect_changed={"ContentType", "LastModified", "VersionId"},
            absent=("code", ("404", "Not Found")),
            delete=lambda: s3.delete_object(Bucket=bucket, Key=obj_key),
        ),
        dict(
            name="sqs_queue",
            create=lambda: state.update(
                qurl=sqs.create_queue(
                    QueueName=f"{p}-q",
                    Attributes={
                        "VisibilityTimeout": "45",
                        "DelaySeconds": "7",
                        "MaximumMessageSize": "262140",
                    },
                )["QueueUrl"]
            )
            or {},
            describe=lambda: sqs.get_queue_attributes(
                QueueUrl=state["qurl"], AttributeNames=["All"]
            ),
            set_fields={
                "Attributes.VisibilityTimeout": "45",
                "Attributes.DelaySeconds": "7",
                "Attributes.MaximumMessageSize": "262140",
            },
            json_paths=set(),
            mutate=lambda: sqs.set_queue_attributes(
                QueueUrl=state["qurl"], Attributes={"VisibilityTimeout": "90"}
            ),
            settled=lambda f: f["Attributes.VisibilityTimeout"] == "90",
            expect_changed={"Attributes.VisibilityTimeout", "Attributes.LastModifiedTimestamp"},
            absent=(
                "code",
                ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."),
            ),
            delete=lambda: sqs.delete_queue(QueueUrl=state["qurl"]),
        ),
        dict(
            name="sns_topic",
            create=lambda: sns.create_topic(
                Name=f"{p}-topic", Attributes={"DisplayName": "sim2real-e3"}
            ),
            describe=lambda: sns.get_topic_attributes(TopicArn=topic_arn),
            set_fields={"Attributes.DisplayName": "sim2real-e3"},
            json_paths=set(),
            mutate=lambda: sns.set_topic_attributes(
                TopicArn=topic_arn, AttributeName="DisplayName", AttributeValue="sim2real-e3-v2"
            ),
            settled=lambda f: f["Attributes.DisplayName"] == "sim2real-e3-v2",
            expect_changed={"Attributes.DisplayName"},
            absent=("code", ("NotFound", "Topic does not exist")),
            delete=lambda: sns.delete_topic(TopicArn=topic_arn),
        ),
        dict(
            name="sns_subscription",
            create=lambda: state.update(
                sub=sns.subscribe(
                    TopicArn=topic_arn,
                    Protocol="sqs",
                    Endpoint=sqs.get_queue_attributes(
                        QueueUrl=state["qurl"], AttributeNames=["QueueArn"]
                    )["Attributes"]["QueueArn"],
                    Attributes={"RawMessageDelivery": "false"},
                    ReturnSubscriptionArn=True,
                )["SubscriptionArn"]
            )
            or {},
            describe=lambda: sns.get_subscription_attributes(SubscriptionArn=state["sub"]),
            set_fields={
                "Attributes.RawMessageDelivery": "false",
                "Attributes.Protocol": "sqs",
            },
            json_paths=set(),
            mutate=lambda: sns.set_subscription_attributes(
                SubscriptionArn=state["sub"],
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            ),
            settled=lambda f: f["Attributes.RawMessageDelivery"] == "true",
            expect_changed={"Attributes.RawMessageDelivery"},
            absent=("code", ("NotFound", "Subscription does not exist")),
            delete=lambda: sns.unsubscribe(SubscriptionArn=state["sub"]),
        ),
        dict(
            name="ssm_parameter",
            create=lambda: ssm.put_parameter(
                Name=param, Type="StringList", Value="alpha,beta,gamma", Description="sim2real e3"
            ),
            describe=lambda: ssm.get_parameter(Name=param),
            set_fields={"Parameter.Type": "StringList", "Parameter.Value": "alpha,beta,gamma"},
            json_paths=set(),
            mutate=lambda: ssm.put_parameter(
                Name=param,
                Type="StringList",
                Value="alpha,beta,delta",
                Description="sim2real e3",
                Overwrite=True,
            ),
            settled=lambda f: f["Parameter.Value"] == "alpha,beta,delta",
            expect_changed={
                "Parameter.Value",
                "Parameter.Version",
                "Parameter.LastModifiedDate",
            },
            absent=("code", ("ParameterNotFound", "")),
            delete=lambda: ssm.delete_parameter(Name=param),
        ),
        dict(
            name="dynamodb_table",
            create=lambda: ddb.create_table(
                TableName=table,
                BillingMode="PAY_PER_REQUEST",
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                TableClass="STANDARD_INFREQUENT_ACCESS",
            ),
            describe=lambda: ddb.describe_table(TableName=table),
            set_fields={
                "Table.TableClassSummary.TableClass": "STANDARD_INFREQUENT_ACCESS",
                "Table.BillingModeSummary.BillingMode": "PAY_PER_REQUEST",
                "Table.KeySchema.0.AttributeName": "pk",
                "Table.KeySchema.0.KeyType": "HASH",
            },
            json_paths=set(),
            mutate=lambda: ddb.update_table(TableName=table, DeletionProtectionEnabled=True),
            settled=lambda f: f.get("Table.DeletionProtectionEnabled") is True
            and f["Table.TableStatus"] == "ACTIVE",
            expect_changed={"Table.DeletionProtectionEnabled"},
            absent=(
                "code",
                ("ResourceNotFoundException", f"Requested resource not found: Table: {table} not found"),
            ),
            delete=lambda: (
                ddb.update_table(TableName=table, DeletionProtectionEnabled=False),
                _poll_until(
                    lambda: ddb.describe_table(TableName=table)["Table"],
                    lambda t: t.get("DeletionProtectionEnabled") is False
                    and t["TableStatus"] == "ACTIVE",
                    timeout_s=180.0,
                    interval_s=2.0,
                    description="deletion protection off before delete_table",
                ),
                ddb.delete_table(TableName=table),
            ),
        ),
        dict(
            name="logs_log_group",
            create=lambda: (
                logs.create_log_group(logGroupName=log_group),
                logs.put_retention_policy(logGroupName=log_group, retentionInDays=3),
            ),
            describe=lambda: _one(
                _paginate(
                    logs, "describe_log_groups", "logGroups", logGroupNamePrefix=log_group
                ),
                lambda g: g["logGroupName"] == log_group,
                f"log group {log_group}",
            ),
            set_fields={"retentionInDays": 3},
            json_paths=set(),
            mutate=lambda: logs.put_retention_policy(logGroupName=log_group, retentionInDays=5),
            settled=lambda f: f["retentionInDays"] == 5,
            expect_changed={"retentionInDays"},
            absent=("empty", None),
            delete=lambda: logs.delete_log_group(logGroupName=log_group),
        ),
        dict(
            name="logs_metric_filter",
            create=lambda: logs.put_metric_filter(**metric_filter(0.0)),
            describe=lambda: _one(
                _paginate(
                    logs,
                    "describe_metric_filters",
                    "metricFilters",
                    logGroupName=log_group,
                    filterNamePrefix=f"{p}-mf",
                ),
                lambda f: f["filterName"] == f"{p}-mf",
                f"metric filter {p}-mf",
            ),
            set_fields={
                "filterPattern": '{ $.level = "ERROR" }',
                "metricTransformations.0.defaultValue": 0.0,
                "metricTransformations.0.unit": "Count",
                "metricTransformations.0.metricValue": "1",
            },
            json_paths=set(),
            mutate=lambda: logs.put_metric_filter(**metric_filter(1.0)),
            settled=lambda f: f["metricTransformations.0.defaultValue"] == 1.0,
            expect_changed={"metricTransformations.0.defaultValue"},
            absent=("empty", None),
            delete=lambda: logs.delete_metric_filter(
                logGroupName=log_group, filterName=f"{p}-mf"
            ),
        ),
        dict(
            name="cloudwatch_metric_alarm",
            create=lambda: cw.put_metric_alarm(**alarm(41.5)),
            describe=lambda: _one(
                _paginate(cw, "describe_alarms", "MetricAlarms", AlarmNames=[f"{p}-alarm"]),
                lambda a: a["AlarmName"] == f"{p}-alarm",
                f"metric alarm {p}-alarm",
            ),
            set_fields={
                "Threshold": 41.5,
                "DatapointsToAlarm": 2,
                "EvaluationPeriods": 3,
                "Period": 60,
                "TreatMissingData": "notBreaching",
            },
            json_paths=set(),
            mutate=lambda: cw.put_metric_alarm(**alarm(50.5)),
            settled=lambda f: f["Threshold"] == 50.5,
            expect_changed={"Threshold", "AlarmConfigurationUpdatedTimestamp"},
            absent=("empty", None),
            delete=lambda: cw.delete_alarms(AlarmNames=[f"{p}-alarm"]),
        ),
        dict(
            name="cloudwatch_composite_alarm",
            create=lambda: cw.put_composite_alarm(
                AlarmName=f"{p}-comp", AlarmRule=f'ALARM("{p}-alarm")', ActionsEnabled=False
            ),
            describe=lambda: _one(
                cw.describe_alarms(AlarmNames=[f"{p}-comp"], AlarmTypes=["CompositeAlarm"])[
                    "CompositeAlarms"
                ],
                lambda a: a["AlarmName"] == f"{p}-comp",
                f"composite alarm {p}-comp",
            ),
            set_fields={"ActionsEnabled": False, "AlarmRule": f'ALARM("{p}-alarm")'},
            json_paths=set(),
            mutate=lambda: cw.put_composite_alarm(
                AlarmName=f"{p}-comp", AlarmRule=f'ALARM("{p}-alarm")', ActionsEnabled=True
            ),
            settled=lambda f: f["ActionsEnabled"] is True,
            expect_changed={"ActionsEnabled", "AlarmConfigurationUpdatedTimestamp"},
            absent=("empty", None),
            delete=lambda: cw.delete_alarms(AlarmNames=[f"{p}-comp"]),
        ),
        dict(
            name="cloudwatch_dashboard",
            create=lambda: cw.put_dashboard(
                DashboardName=f"{p}-dash", DashboardBody=json.dumps(dash_body)
            ),
            describe=lambda: cw.get_dashboard(DashboardName=f"{p}-dash"),
            set_fields={"DashboardBody": dash_body},
            json_paths={"DashboardBody"},
            mutate=lambda: cw.put_dashboard(
                DashboardName=f"{p}-dash", DashboardBody=json.dumps(dash_body_v2)
            ),
            settled=lambda f: json.loads(f["DashboardBody"])["widgets"][0]["properties"][
                "markdown"
            ]
            == "sim2real-e3-v2",
            expect_changed={"DashboardBody"},
            absent=("code", ("ResourceNotFound", f"Dashboard {p}-dash does not exist")),
            delete=lambda: cw.delete_dashboards(DashboardNames=[f"{p}-dash"]),
        ),
        dict(
            name="secretsmanager_secret",
            create=lambda: sm.create_secret(
                Name=f"{p}-secret",
                Description="sim2real e3",
                SecretString=json.dumps({"user": "e3"}),
            ),
            describe=lambda: sm.describe_secret(SecretId=f"{p}-secret"),
            set_fields={"Description": "sim2real e3", "Name": f"{p}-secret"},
            json_paths=set(),
            mutate=lambda: sm.update_secret(
                SecretId=f"{p}-secret", Description="sim2real e3 v2"
            ),
            settled=lambda f: f["Description"] == "sim2real e3 v2",
            expect_changed={"Description", "LastChangedDate"},
            absent=(
                "code",
                ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."),
            ),
            delete=lambda: sm.delete_secret(
                SecretId=f"{p}-secret", ForceDeleteWithoutRecovery=True
            ),
        ),
        dict(
            name="events_rule",
            create=lambda: ev.put_rule(
                Name=f"{p}-rule",
                State="DISABLED",
                Description="sim2real e3",
                EventPattern=json.dumps({"source": ["sim2real.e3"]}),
            ),
            describe=lambda: ev.describe_rule(Name=f"{p}-rule"),
            set_fields={
                "State": "DISABLED",
                "Description": "sim2real e3",
                "EventPattern": {"source": ["sim2real.e3"]},
            },
            json_paths={"EventPattern"},
            mutate=lambda: ev.enable_rule(Name=f"{p}-rule"),
            settled=lambda f: f["State"] == "ENABLED",
            expect_changed={"State"},
            absent=(
                "code",
                ("ResourceNotFoundException", f"Rule {p}-rule does not exist on EventBus default."),
            ),
            delete=lambda: ev.delete_rule(Name=f"{p}-rule"),
        ),
        dict(
            name="iam_role",
            create=lambda: iam.create_role(
                RoleName=f"{p}-role",
                MaxSessionDuration=4711,
                Description="sim2real e3",
                AssumeRolePolicyDocument=json.dumps(trust),
            ),
            describe=lambda: iam.get_role(RoleName=f"{p}-role"),
            set_fields={
                "Role.MaxSessionDuration": 4711,
                "Role.Description": "sim2real e3",
                "Role.AssumeRolePolicyDocument.Statement.0.Principal.Service":
                    "events.amazonaws.com",
                "Role.AssumeRolePolicyDocument.Statement.0.Action": "sts:AssumeRole",
            },
            json_paths=set(),
            mutate=lambda: iam.update_role(RoleName=f"{p}-role", MaxSessionDuration=7200),
            settled=lambda f: f["Role.MaxSessionDuration"] == 7200,
            expect_changed={"Role.MaxSessionDuration"},
            absent=("code", ("NoSuchEntity", f"The role with name {p}-role cannot be found.")),
            delete=lambda: iam.delete_role(RoleName=f"{p}-role"),
        ),
        dict(
            name="iam_policy",
            create=lambda: iam.create_policy(
                PolicyName=f"{p}-pol",
                Description="sim2real e3",
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            ),
            describe=lambda: iam.get_policy(PolicyArn=policy_arn),
            set_fields={
                "Policy.Description": "sim2real e3",
                "Policy.PolicyName": f"{p}-pol",
                "Policy.DefaultVersionId": "v1",
            },
            json_paths=set(),
            mutate=lambda: iam.create_policy_version(
                PolicyArn=policy_arn,
                SetAsDefault=True,
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sqs:ReceiveMessage",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
            ),
            settled=lambda f: f["Policy.DefaultVersionId"] == "v2",
            expect_changed={"Policy.DefaultVersionId", "Policy.UpdateDate"},
            absent=("code", ("NoSuchEntity", f"Policy {policy_arn} was not found.")),
            # MEASURED: DeletePolicy raises DeleteConflict while a non-default version exists, and
            # this row's mutation deliberately creates one. The non-default versions have to go
            # first, or the check leaks the policy.
            delete=lambda: _delete_policy_with_versions(iam, policy_arn),
        ),
        dict(
            name="ecr_repository",
            create=lambda: ecr.create_repository(
                repositoryName=f"{p}-repo",
                imageTagMutability="IMMUTABLE",
                imageScanningConfiguration={"scanOnPush": True},
            ),
            describe=lambda: _one(
                ecr.describe_repositories(repositoryNames=[f"{p}-repo"])["repositories"],
                lambda r: r["repositoryName"] == f"{p}-repo",
                f"ecr repository {p}-repo",
            ),
            set_fields={
                "imageTagMutability": "IMMUTABLE",
                "imageScanningConfiguration.scanOnPush": True,
            },
            json_paths=set(),
            mutate=lambda: ecr.put_image_tag_mutability(
                repositoryName=f"{p}-repo", imageTagMutability="MUTABLE"
            ),
            settled=lambda f: f["imageTagMutability"] == "MUTABLE",
            expect_changed={"imageTagMutability"},
            absent=(
                "code",
                (
                    "RepositoryNotFoundException",
                    f"The repository with name '{p}-repo' does not exist in the registry with id "
                    f"'{acct}'",
                ),
            ),
            delete=lambda: ecr.delete_repository(repositoryName=f"{p}-repo", force=True),
        ),
        dict(
            name="ecr_lifecycle_policy",
            create=lambda: ecr.put_lifecycle_policy(
                repositoryName=f"{p}-repo", lifecyclePolicyText=json.dumps(ecr_policy(7))
            ),
            describe=lambda: ecr.get_lifecycle_policy(repositoryName=f"{p}-repo"),
            set_fields={"lifecyclePolicyText": ecr_policy(7)},
            json_paths={"lifecyclePolicyText"},
            mutate=lambda: ecr.put_lifecycle_policy(
                repositoryName=f"{p}-repo", lifecyclePolicyText=json.dumps(ecr_policy(9))
            ),
            settled=lambda f: json.loads(f["lifecyclePolicyText"])["rules"][0]["selection"][
                "countNumber"
            ]
            == 9,
            expect_changed={"lifecyclePolicyText"},
            absent=(
                "code",
                (
                    "LifecyclePolicyNotFoundException",
                    f"Lifecycle policy does not exist for the repository with name '{p}-repo' in "
                    f"the registry with id '{acct}'",
                ),
            ),
            delete=lambda: ecr.delete_lifecycle_policy(repositoryName=f"{p}-repo"),
        ),
    ]

    assert len(rows) == _ROW_COUNT, (
        f"the table declares {len(rows)} rows, expected {_ROW_COUNT}"
    )
    names = [r["name"] for r in rows]
    assert len(set(names)) == _ROW_COUNT, f"duplicate row names: {names}"

    # ------------------------------------------------------------------ phase A: create everything
    created: list[dict] = []
    for r in rows:
        resp = r["create"]()
        # Cleanup registered IMMEDIATELY after the create it undoes, before the next assertion, so a
        # failing assertion cannot leak. LIFO, so the dependent rows registered later run first.
        ctx.on_cleanup(_undo(r))
        created.append(r)
        r["create_flat"] = _flatten(_strip(resp)) if isinstance(resp, dict) else {}
    assert len(created) == _ROW_COUNT, f"only {len(created)} of {_ROW_COUNT} rows were created"
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # ------------------------------------ phase B: describe #1, and the two per-row value invariants
    d1: dict[str, dict] = {}
    missing: list[str] = []
    wrong: list[str] = []
    typed: list[str] = []
    shared_total = 0
    disagreed: list[str] = []
    for r in rows:
        flat = _flatten(_strip(r["describe"]()))
        d1[r["name"]] = flat
        for path, want in r["set_fields"].items():
            if path not in flat:
                missing.append(f"{r['name']}:{path}")
                continue
            got = flat[path]
            if path in r["json_paths"]:
                got = json.loads(got)
            if got != want:
                wrong.append(f"{r['name']}:{path} = {got!r}, expected {want!r}")
            elif type(got) is not type(want):
                typed.append(
                    f"{r['name']}:{path} came back as {type(got).__name__} "
                    f"{got!r}, expected {type(want).__name__} {want!r}"
                )
        for path, cval in r["create_flat"].items():
            if path in flat:
                shared_total += 1
                if flat[path] != cval:
                    disagreed.append(
                        f"{r['name']}:{path} create={cval!r} describe={flat[path]!r}"
                    )
    assert missing == [], (
        "attributes the caller set are ABSENT from the describe response — an endpoint that accepts "
        f"a value on create and drops it on read produces a permanent diff: {missing}"
    )
    assert wrong == [], (
        f"attributes did not round-trip with the value the caller set: {wrong}"
    )
    assert typed == [], (
        "attributes round-tripped with the right value but the WRONG Python type; a provider treats "
        f"'45' and 45 as different values and diffs on it forever: {typed}"
    )
    assert disagreed == [], (
        "the create response and the first describe disagree on a field they BOTH return — this is "
        f"literally the provider's post-apply consistency check: {disagreed}"
    )
    # Anti-vacuity floor for the assertion above: 28 create/describe field overlaps were measured
    # across these 23 rows on real AWS. The claim is `disagreed == []`; this floor only guarantees
    # the intersection is not empty, which would make that claim vacuous.
    assert shared_total >= 20, (
        f"only {shared_total} create-response fields also appear in a describe response; 28 were "
        "measured, so an intersection this small means the create responses were not captured and "
        "the agreement assertion above is vacuous"
    )

    # ------------------- phase C: describe #2 must be DEEPLY identical to #1 modulo the volatile set
    # Not a wait for a condition: the 20 s gap is the measurement. A read path that regenerates a
    # field per request, or caches with a TTL under 20 s, differs from describe #1, and a poll would
    # hide that. _VOLATILE was measured over this same gap.
    time.sleep(20)
    d2: dict[str, dict] = {}
    unstable: list[str] = []
    for r in rows:
        flat = _flatten(_strip(r["describe"]()))
        d2[r["name"]] = flat
        for path in _diff(d1[r["name"]], flat, _VOLATILE.get(r["name"], set())):
            unstable.append(
                f"{r['name']}:{path} moved from {d1[r['name']].get(path)!r} to "
                f"{flat.get(path)!r} between two consecutive describes"
            )
    assert unstable == [], (
        "two consecutive describes of an untouched resource disagree. A field regenerated per read "
        "makes terraform plan non-empty forever even when every attribute is individually correct, "
        f"and it is the failure users report as intermittent: {unstable}"
    )

    # ------- phase D: CONTROL. One out-of-band mutation per row must show up, and change NOTHING else
    for r in rows:
        r["mutate"]()
    unsettled: list[str] = []
    for r in rows:
        try:
            _poll_until(
                lambda r=r: _flatten(_strip(r["describe"]())),
                lambda f, r=r: r["settled"](f),
                timeout_s=180.0,
                interval_s=2.0,
                description=f"{r['name']} reflects its out-of-band mutation",
            )
        except AssertionError as exc:
            unsettled.append(f"{r['name']}: {exc}")
    assert unsettled == [], (
        f"an out-of-band mutation never became visible on read: {unsettled}"
    )
    overreach: list[str] = []
    for r in rows:
        flat = _flatten(_strip(r["describe"]()))
        changed = set(_diff(d2[r["name"]], flat, _VOLATILE.get(r["name"], set())))
        if changed != r["expect_changed"]:
            overreach.append(
                f"{r['name']}: changed paths {sorted(changed)}, expected exactly "
                f"{sorted(r['expect_changed'])}"
            )
    assert overreach == [], (
        "a single-field mutation changed a different set of paths than the one measured against "
        "real AWS. This is the control that proves phase C is not passing because the endpoint "
        f"returns a frozen blob: {overreach}"
    )

    # ------------------------------------- phase E: delete, then the EXACT documented absence signal
    absent_failures: list[str] = []
    for r in reversed(rows):
        r["delete"]()
        kind, spec = r["absent"]
        try:
            if kind == "code":
                _poll_for_client_error(
                    r["describe"], *spec, f"{r['name']} after delete", timeout_s=180.0
                )
            elif kind == "empty":
                _poll_until(
                    lambda r=r: _absent_list(r),
                    lambda gone: gone is True,
                    timeout_s=180.0,
                    interval_s=2.0,
                    description=f"{r['name']} absent from its List*/Describe* after delete",
                )
            else:  # "default" -- AWS reverts to a documented service default rather than 404ing
                _poll_until(
                    lambda r=r: _flatten(_strip(r["describe"]())),
                    lambda f, spec=spec: all(f.get(k) == v for k, v in spec.items()),
                    timeout_s=180.0,
                    interval_s=2.0,
                    description=f"{r['name']} reverted to the documented AWS default {spec}",
                )
        except AssertionError as exc:
            absent_failures.append(f"{r['name']}: {exc}")
    assert absent_failures == [], (
        f"a deleted resource did not report its documented absence signal: {absent_failures}"
    )
    assert len(rows) == _ROW_COUNT, "row table mutated during the run"


# ===== helpers =====


def _strip(resp: dict) -> dict:
    out = dict(resp)
    out.pop("ResponseMetadata", None)
    return out


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Every LEAF of a response, keyed by its dotted path (list indices included), so a deep
    comparison names the exact path that differs instead of dumping two whole documents."""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, f"{prefix}.{i}" if prefix else str(i)))
    else:
        out[prefix] = obj
    return out


def _diff(a: dict[str, Any], b: dict[str, Any], volatile: set[str]) -> list[str]:
    """Paths where two flattened responses differ, ignoring an explicitly named volatile set.
    List ORDER matters: a reordered list changes the index in the path, so it is reported."""
    return sorted(
        k
        for k in set(a) | set(b)
        if k not in volatile and (k not in a or k not in b or a[k] != b[k])
    )


class _NoMatch(AssertionError):
    """A list response held no entry for the resource: the post-delete state of a list row."""


def _one(items: list, predicate, description: str) -> dict:
    """The single matching entry of a list response, asserted to be exactly one."""
    hits = [i for i in items if predicate(i)]
    if not hits:
        raise _NoMatch(f"expected exactly one {description}; none of {len(items)} entries matched")
    assert len(hits) == 1, (
        f"expected exactly one {description}; the list held {len(hits)} matches out of "
        f"{len(items)} entries"
    )
    return hits[0]


def _absent_list(row) -> bool:
    """True when a list-shaped describe no longer returns the row's resource.

    `_one` raises `_NoMatch` when there are zero matches, which is exactly the post-delete state;
    anything ELSE that goes wrong must not be read as absence, so only that signal is treated as gone.
    A ResourceNotFoundException from the enclosing container (a metric filter's log group already
    deleted) is also absence.
    """
    try:
        row["describe"]()
    except _NoMatch:
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ResourceNotFoundException":
            return True
        raise
    return False


def _undo(row):
    """A cleanup callable that undoes the row's create and raises when the delete is refused.

    The delete is idempotent by outcome: the check itself deletes every row in phase E, so the
    normal path is a not-found answer, which counts as deleted.
    """

    def _fn() -> None:
        try:
            row["delete"]()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _ABSENT_CODES:
                return
            raise RuntimeError(f"{row['name']} not deleted: {exc}") from exc
        except AssertionError:
            return

    return _fn


_ABSENT_CODES = {
    "404",
    "AWS.SimpleQueueService.NonExistentQueue",
    "InvalidParameterValue",
    "LifecyclePolicyNotFoundException",
    "NoSuchBucketPolicy",
    "NoSuchCORSConfiguration",
    "NoSuchEntity",
    "NoSuchKey",
    "NoSuchLifecycleConfiguration",
    "NoSuchPublicAccessBlockConfiguration",
    "NotFound",
    "OwnershipControlsNotFoundError",
    "ParameterNotFound",
    "RepositoryNotFoundException",
    "ResourceNotFound",
    "ResourceNotFoundException",
}


def _delete_policy_with_versions(iam, policy_arn: str) -> None:
    """Delete every non-default version, then the policy (whose default version goes with it)."""
    for v in _paginate(iam, "list_policy_versions", "Versions", PolicyArn=policy_arn):
        if not v["IsDefaultVersion"]:
            iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
    iam.delete_policy(PolicyArn=policy_arn)


def _paginate(client, op: str, key: str, **kwargs) -> list:
    """Exhaust a List*/Describe* whose result is asserted on. The account may be shared, so
    other resources can push ours off page one."""
    if client.can_paginate(op):
        items: list = []
        for page in client.get_paginator(op).paginate(**kwargs):
            items.extend(page.get(key, []))
        return items
    return list(getattr(client, op)(**kwargs).get(key, []))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _poll_for_client_error(
    fn, code: str, message: str, description: str, *, timeout_s=120.0, interval_s=2.0
):
    """Poll fn() until it raises ClientError with EXACTLY *code* and *message* (deletions are
    eventual).

    A single expected code and message, never a tuple. A call that keeps SUCCEEDING past the deadline is
    reported as still-succeeding rather than as a code mismatch: the resource is still there, which
    is the strongest signal available and must not read like a naming difference.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            got = exc.response.get("Error", {}).get("Code", "")
            if got != code:
                raise AssertionError(
                    f"{description}: expected error code {code!r}, got {got!r} ({exc})"
                )
            said = exc.response.get("Error", {}).get("Message")
            if said != message:
                raise AssertionError(f"{description}: {code} message {said!r}, expected {message!r}")
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: still succeeding after {timeout_s}s; expected {code!r}."
            )
        time.sleep(interval_s)


def _purge_bucket(s3, bucket: str) -> None:
    """Delete every version and delete-marker, then the bucket. A versioned bucket cannot be deleted
    while any version remains, and a silent failure here leaks a bucket forever."""
    try:
        while True:
            page = s3.list_object_versions(Bucket=bucket, MaxKeys=1000)
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if not objs:
                break
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchBucket",):
            raise RuntimeError(f"bucket {bucket!r} not deleted: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
