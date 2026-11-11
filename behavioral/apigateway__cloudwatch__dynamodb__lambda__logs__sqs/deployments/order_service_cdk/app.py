#!/usr/bin/env python3
"""CDK app: the order-intake reference application, asset-free.

The same application the sibling order_service_cfn.yaml / order_service_sam.yaml /
order_service_tf modules build: POST /orders -> intake function -> DynamoDB row + SQS message ->
event-source mapping -> worker function -> row fulfilled + OrdersFulfilled metric -> alarm.

ASSET-FREE BY CONSTRUCTION. The check deploys this through `cdk synth` -> strip the BootstrapVersion
parameter and CheckBootstrapVersion rule -> plain create_stack, which hard-fails if the synthesized
template references a file or image asset. So the handlers are `Code.from_inline` strings (character
identical to the other three flavors' copies), the log groups are declared directly instead of via
`log_retention` (which synthesizes a custom-resource Lambda, and therefore an asset), and the API's
account-level CloudWatch role is disabled (it is an account-wide singleton that concurrent checks
would fight over).

Every name arrives as a synth-time context value so the four flavors deploy the SAME named
application; the resource names are the check's `ctx.unique_name("sim2real-xsvc-...")` values.

Context keys (passed via `cdk synth --context <Key>=<value>`), deliberately spelled in the
CloudFormation parameter case the check's one canonical parameter dict uses, so this flavor needs no
name mapping of its own:
  TableName, QueueName, IntakeFunctionName, WorkerFunctionName, IntakeRoleName, WorkerRoleName,
  ApiName, StageName, AlarmName, MetricNamespace, IntakeMemorySize
"""
from aws_cdk import App, CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_lambda_event_sources as lambda_event_sources
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sqs as sqs

INTAKE_CODE = """
import json
import os
import boto3

_ddb = boto3.client("dynamodb")
_sqs = boto3.client("sqs")


def handler(event, context):
    body = json.loads(event.get("body") or "{}")
    order_id = body["orderId"]
    _ddb.put_item(
        TableName=os.environ["TABLE_NAME"],
        Item={"orderId": {"S": order_id}, "status": {"S": "received"}},
    )
    _sqs.send_message(
        QueueUrl=os.environ["QUEUE_URL"],
        MessageBody=json.dumps({"orderId": order_id}),
    )
    print(json.dumps({"app": "order-intake", "stage": "intake", "orderId": order_id, "status": "received"}))
    return {
        "statusCode": 202,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({"orderId": order_id, "status": "received"}),
    }
"""

# The ClientError arm reports the denial and CONSUMES the message rather than re-raising. Re-raising
# returns the batch to the queue and, with no redrive policy, the event-source mapping would
# re-deliver it for the rest of the run -- so the denial leg's own message would be fulfilled
# retroactively the moment the Deny is removed.
WORKER_CODE = """
import json
import os
import boto3
from botocore.exceptions import ClientError

_ddb = boto3.client("dynamodb")
_cw = boto3.client("cloudwatch")


def handler(event, context):
    for record in event.get("Records", []):
        order_id = json.loads(record["body"])["orderId"]
        try:
            _ddb.update_item(
                TableName=os.environ["TABLE_NAME"],
                Key={"orderId": {"S": order_id}},
                UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": {"S": "fulfilled"}},
                ConditionExpression="attribute_exists(orderId)",
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            print(json.dumps({"app": "order-intake", "stage": "worker", "orderId": order_id, "status": "denied", "op": "UpdateItem", "code": code, "message": exc.response["Error"].get("Message")}))
            continue
        _cw.put_metric_data(
            Namespace=os.environ["METRIC_NAMESPACE"],
            MetricData=[{"MetricName": "OrdersFulfilled", "Value": 1.0, "Unit": "Count"}],
        )
        print(json.dumps({"app": "order-intake", "stage": "worker", "orderId": order_id, "status": "fulfilled"}))
    return {"ok": True}
"""


class OrderServiceStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, analytics_reporting=False, **kwargs)
        ctx = self.node.try_get_context

        table_name = ctx("TableName")
        queue_name = ctx("QueueName")
        intake_name = ctx("IntakeFunctionName")
        worker_name = ctx("WorkerFunctionName")
        intake_role_name = ctx("IntakeRoleName")
        worker_role_name = ctx("WorkerRoleName")
        api_name = ctx("ApiName")
        stage_name = ctx("StageName")
        alarm_name = ctx("AlarmName")
        metric_namespace = ctx("MetricNamespace")
        intake_memory = int(ctx("IntakeMemorySize"))

        # DESTROY, not the L2 default: a RETAINed table survives the teardown leg, which asserts the
        # table is GONE after the destroy.
        table = dynamodb.Table(
            self,
            "Table",
            table_name=table_name,
            partition_key=dynamodb.Attribute(
                name="orderId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )
        queue = sqs.Queue(
            self,
            "Queue",
            queue_name=queue_name,
            # Longer than the function timeout, so a message is never handed to a second poller
            # while the first invocation still holds it.
            visibility_timeout=Duration.seconds(60),
            retention_period=Duration.hours(1),
        )

        intake_log_group = logs.LogGroup(
            self,
            "IntakeLogGroup",
            log_group_name=f"/aws/lambda/{intake_name}",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        worker_log_group = logs.LogGroup(
            self,
            "WorkerLogGroup",
            log_group_name=f"/aws/lambda/{worker_name}",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Named roles, granted by hand rather than through the L2 grant helpers, so the four flavors
        # carry the SAME action set: the denial leg attaches an explicit Deny for
        # dynamodb:UpdateItem to the worker role by name, and it needs the Allow it overrides to be
        # present and scoped for the negative to mean anything.
        log_statement = iam.PolicyStatement(
            actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            resources=["*"],
        )
        intake_role = iam.Role(
            self,
            "IntakeRole",
            role_name=intake_role_name,
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "intake": iam.PolicyDocument(
                    statements=[
                        log_statement,
                        iam.PolicyStatement(
                            actions=["dynamodb:PutItem"], resources=[table.table_arn]
                        ),
                        iam.PolicyStatement(
                            actions=["sqs:SendMessage"], resources=[queue.queue_arn]
                        ),
                    ]
                )
            },
        )
        worker_role = iam.Role(
            self,
            "WorkerRole",
            role_name=worker_role_name,
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            inline_policies={
                "worker": iam.PolicyDocument(
                    statements=[
                        log_statement,
                        iam.PolicyStatement(
                            actions=["dynamodb:UpdateItem"], resources=[table.table_arn]
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "sqs:ReceiveMessage",
                                "sqs:DeleteMessage",
                                "sqs:GetQueueAttributes",
                                "sqs:ChangeMessageVisibility",
                            ],
                            resources=[queue.queue_arn],
                        ),
                        iam.PolicyStatement(
                            actions=["cloudwatch:PutMetricData"], resources=["*"]
                        ),
                    ]
                )
            },
        )

        intake_fn = _lambda.Function(
            self,
            "IntakeFunction",
            function_name=intake_name,
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(INTAKE_CODE),
            role=intake_role,
            memory_size=intake_memory,
            timeout=Duration.seconds(20),
            environment={"TABLE_NAME": table_name, "QUEUE_URL": queue.queue_url},
        )
        intake_fn.node.add_dependency(intake_log_group)

        worker_fn = _lambda.Function(
            self,
            "WorkerFunction",
            function_name=worker_name,
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(WORKER_CODE),
            role=worker_role,
            memory_size=128,
            timeout=Duration.seconds(20),
            environment={
                "TABLE_NAME": table_name,
                "METRIC_NAMESPACE": metric_namespace,
            },
        )
        worker_fn.node.add_dependency(worker_log_group)
        worker_fn.add_event_source(
            lambda_event_sources.SqsEventSource(queue, batch_size=1, enabled=True)
        )

        api = apigateway.RestApi(
            self,
            "Api",
            rest_api_name=api_name,
            endpoint_types=[apigateway.EndpointType.REGIONAL],
            # An account-wide singleton; concurrent checks would fight over it.
            cloud_watch_role=False,
            deploy_options=apigateway.StageOptions(stage_name=stage_name),
        )
        api.root.add_resource("orders").add_method(
            "POST", apigateway.LambdaIntegration(intake_fn)
        )

        # TreatMissingData.MISSING is what makes the alarm start in INSUFFICIENT_DATA, which is the
        # transition the alarm leg reads out of the state history. No actions: the assertion path is
        # the alarm's own state, so the application needs no SNS topic to stay identical across the
        # four flavors.
        cloudwatch.Alarm(
            self,
            "FulfilledAlarm",
            alarm_name=alarm_name,
            metric=cloudwatch.Metric(
                namespace=metric_namespace,
                metric_name="OrdersFulfilled",
                statistic="Sum",
                period=Duration.seconds(60),
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.MISSING,
            actions_enabled=False,
        )

        CfnOutput(self, "ApiId", value=api.rest_api_id)


app = App()
OrderServiceStack(app, "OrderServiceStack")
app.synth()
