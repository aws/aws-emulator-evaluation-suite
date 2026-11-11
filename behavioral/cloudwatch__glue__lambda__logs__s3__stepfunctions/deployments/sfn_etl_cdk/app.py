#!/usr/bin/env python3
"""CDK app: a Step Functions ETL over S3 with a Glue catalog table, driven by TWO directory assets.

  ``<prefix>-main``    extract -> Choice -> transform, each stage a Lambda whose code is its own
                       published asset. The transform stage writes the curated partition object and
                       registers the partition in the Glue table, and prints the line a Logs metric
                       filter turns into the custom metric the alarm watches. The state machine
                       itself logs to CloudWatch Logs at ALL.
  ``<prefix>-broken``  the same two published functions, orchestrated by a hand-written ASL
                       definition whose execution role may invoke EXTRACT ONLY. The execution
                       therefore reaches the transform hop and is refused there by name, and no
                       curated object appears for its batch.

Two assets rather than one is deliberate: the drift legs assert per-asset content addressing, which
needs one asset whose content changes and one whose content does not, in the same deploy.

The data bucket is EXTERNAL (created by the check, imported here) so that it survives `cdk destroy`
and the teardown leg can assert an absence at the destination rather than only that the state
machine 404s.

Context:
  stack_prefix    — CloudFormation stack name prefix (carries the cleanup prefix `sim2real-xsvc-`).
  data_bucket     — external bucket holding raw/, manifests/ and curated/.
  glue_database / glue_table — external-facing catalog names, created by this stack.
  metric_namespace — per-run namespace for the metric-filter metric.
  min_records     — the Choice threshold. The drift knob: it changes the state machine's DEFINITION,
                    which must be an in-place update rather than a replacement.
  stage           — the transform stage's environment tag; the second drift knob, observable in the
                    curated rows.
  extract_arn / transform_arn — the main stack's function ARNs, passed to the BROKEN stack so it can
                    orchestrate the already-published assets without publishing anything new.
"""
import json

from aws_cdk import App, CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_glue as glue
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks

METRIC_NAME = "CuratedBatches"
RAW_PREFIX = "raw/"
MANIFEST_PREFIX = "manifests/"
CURATED_PREFIX = "curated/"
# The literal the transform handler prints and the metric filter counts. Fixed, not per-run: the
# filter is part of the deployed stack and must not change between deploys, or the drift leg would
# be comparing two different filters.
LOG_TOKEN = "SIM2REAL_CURATED"


def _ctx(scope, key, default=""):
    value = scope.node.try_get_context(key)
    return default if value in (None, "") else value


class SfnEtlStack(Stack):
    """The wired pipeline."""

    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        bucket_name = _ctx(self, "data_bucket")
        bucket = s3.Bucket.from_bucket_name(self, "Data", bucket_name)
        database_name = _ctx(self, "glue_database")
        table_name = _ctx(self, "glue_table")
        namespace = _ctx(self, "metric_namespace", "sim2real/xsvc")
        min_records = int(_ctx(self, "min_records", "1"))

        database = glue.CfnDatabase(
            self,
            "Database",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(name=database_name),
        )
        table = glue.CfnTable(
            self,
            "Table",
            catalog_id=self.account,
            database_name=database_name,
            table_input=glue.CfnTable.TableInputProperty(
                name=table_name,
                table_type="EXTERNAL_TABLE",
                parameters={"classification": "json"},
                partition_keys=[glue.CfnTable.ColumnProperty(name="batch", type="string")],
                storage_descriptor=glue.CfnTable.StorageDescriptorProperty(
                    location=f"s3://{bucket_name}/{CURATED_PREFIX}",
                    input_format="org.apache.hadoop.mapred.TextInputFormat",
                    output_format=(
                        "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
                    ),
                    serde_info=glue.CfnTable.SerdeInfoProperty(
                        serialization_library="org.openx.data.jsonserde.JsonSerDe"
                    ),
                    columns=[
                        glue.CfnTable.ColumnProperty(name="id", type="string"),
                        glue.CfnTable.ColumnProperty(name="value", type="string"),
                        glue.CfnTable.ColumnProperty(name="digest", type="string"),
                        glue.CfnTable.ColumnProperty(name="stage", type="string"),
                    ],
                ),
            ),
        )
        table.node.add_dependency(database)

        extract_logs = logs.LogGroup(
            self,
            "ExtractLogs",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        transform_logs = logs.LogGroup(
            self,
            "TransformLogs",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        extract = _lambda.Function(
            self,
            "Extract",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset("extract"),
            timeout=Duration.seconds(60),
            log_group=extract_logs,
            environment={"MANIFEST_PREFIX": MANIFEST_PREFIX},
        )
        transform = _lambda.Function(
            self,
            "Transform",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset("transform"),
            timeout=Duration.seconds(60),
            log_group=transform_logs,
            environment={
                "DATA_BUCKET": bucket_name,
                "CURATED_PREFIX": CURATED_PREFIX,
                "GLUE_DATABASE": database_name,
                "GLUE_TABLE": table_name,
                "STAGE": _ctx(self, "stage", "alpha"),
            },
        )
        bucket.grant_read_write(extract)
        bucket.grant_read_write(transform)
        extract_logs.grant_write(extract)
        transform_logs.grant_write(transform)
        transform.add_to_role_policy(
            iam.PolicyStatement(
                actions=["glue:GetTable", "glue:GetPartition", "glue:CreatePartition"],
                resources=[
                    self.format_arn(service="glue", resource="catalog"),
                    self.format_arn(service="glue", resource="database", resource_name=database_name),
                    self.format_arn(
                        service="glue", resource="table", resource_name=f"{database_name}/{table_name}"
                    ),
                ],
            )
        )

        extract_task = tasks.LambdaInvoke(
            self,
            "ExtractStage",
            lambda_function=extract,
            payload=sfn.TaskInput.from_object(
                {
                    "bucket": sfn.JsonPath.string_at("$.bucket"),
                    "key": sfn.JsonPath.string_at("$.key"),
                    "batch": sfn.JsonPath.string_at("$.batch"),
                }
            ),
            payload_response_only=True,
            result_path="$.extract",
        )
        transform_task = tasks.LambdaInvoke(
            self,
            "TransformStage",
            lambda_function=transform,
            payload=sfn.TaskInput.from_object(
                {
                    "manifest": sfn.JsonPath.string_at("$.extract.manifest"),
                    "batch": sfn.JsonPath.string_at("$.batch"),
                }
            ),
            payload_response_only=True,
            result_path="$.transform",
        )
        definition = extract_task.next(
            sfn.Choice(self, "EnoughRecords")
            .when(
                sfn.Condition.number_greater_than_equals("$.extract.count", min_records),
                transform_task.next(sfn.Succeed(self, "Curated")),
            )
            .otherwise(
                sfn.Fail(
                    self,
                    "EmptyBatch",
                    error="EmptyBatch",
                    cause="the extract stage produced fewer records than the deployed threshold",
                )
            )
        )
        machine_logs = logs.LogGroup(
            self,
            "MachineLogs",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        machine = sfn.StateMachine(
            self,
            "Etl",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.minutes(10),
            logs=sfn.LogOptions(
                destination=machine_logs, level=sfn.LogLevel.ALL, include_execution_data=True
            ),
        )

        metric_filter = logs.MetricFilter(
            self,
            "CuratedFilter",
            log_group=transform_logs,
            filter_pattern=logs.FilterPattern.literal(f'"{LOG_TOKEN}"'),
            metric_namespace=namespace,
            metric_name=METRIC_NAME,
            metric_value="1",
        )
        alarm = cloudwatch.Alarm(
            self,
            "CuratedAlarm",
            metric=metric_filter.metric(statistic="Sum", period=Duration.minutes(1)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            # MISSING so the alarm STARTS in INSUFFICIENT_DATA and the crossing is assertable.
            treat_missing_data=cloudwatch.TreatMissingData.MISSING,
        )

        CfnOutput(self, "StateMachineArn", value=machine.state_machine_arn)
        CfnOutput(self, "MachineLogGroupName", value=machine_logs.log_group_name)
        CfnOutput(self, "ExtractFunctionName", value=extract.function_name)
        CfnOutput(self, "ExtractFunctionArn", value=extract.function_arn)
        CfnOutput(self, "TransformFunctionName", value=transform.function_name)
        CfnOutput(self, "TransformFunctionArn", value=transform.function_arn)
        CfnOutput(self, "TransformLogGroupName", value=transform_logs.log_group_name)
        CfnOutput(self, "AlarmName", value=alarm.alarm_name)
        CfnOutput(self, "MetricNamespace", value=namespace)
        CfnOutput(self, "MetricName", value=METRIC_NAME)
        CfnOutput(self, "DataBucket", value=bucket_name)
        CfnOutput(self, "DatabaseName", value=database_name)
        CfnOutput(self, "TableName", value=table_name)
        CfnOutput(self, "RawPrefix", value=RAW_PREFIX)
        CfnOutput(self, "CuratedPrefix", value=CURATED_PREFIX)
        CfnOutput(self, "MinRecords", value=str(min_records))
        CfnOutput(self, "Stage", value=_ctx(self, "stage", "alpha"))


class SfnEtlBrokenStack(Stack):
    """The same two published assets, orchestrated by a role that may invoke only the first.

    Hand-written ASL and a hand-built role on purpose: the `LambdaInvoke` construct grants
    `lambda:InvokeFunction` to the state machine automatically, so the only way to express "exactly
    one permission is missing" is to write the definition and the policy out.
    """

    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        extract_arn = _ctx(self, "extract_arn")
        transform_arn = _ctx(self, "transform_arn")

        role = iam.Role(self, "BrokenRole", assumed_by=iam.ServicePrincipal("states.amazonaws.com"))
        role.add_to_policy(
            iam.PolicyStatement(
                actions=["lambda:InvokeFunction"],
                resources=[extract_arn, f"{extract_arn}:*"],
            )
        )
        definition = {
            "StartAt": "Extract",
            "States": {
                "Extract": {
                    "Type": "Task",
                    "Resource": extract_arn,
                    "ResultPath": "$.extract",
                    "Next": "Transform",
                },
                "Transform": {
                    "Type": "Task",
                    "Resource": transform_arn,
                    "Parameters": {
                        "manifest.$": "$.extract.manifest",
                        "batch.$": "$.batch",
                    },
                    "End": True,
                },
            },
        }
        machine = sfn.CfnStateMachine(
            self,
            "BrokenEtl",
            role_arn=role.role_arn,
            definition_string=json.dumps(definition),
        )
        machine.node.add_dependency(role)

        CfnOutput(self, "BrokenStateMachineArn", value=machine.ref)


app = App()
_PREFIX = app.node.try_get_context("stack_prefix") or "SimParityCdkSfnEtl"
SfnEtlStack(app, f"{_PREFIX}-main")
SfnEtlBrokenStack(app, f"{_PREFIX}-broken")
app.synth()
