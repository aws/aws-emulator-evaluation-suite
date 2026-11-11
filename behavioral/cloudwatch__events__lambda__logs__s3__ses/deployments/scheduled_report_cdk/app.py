#!/usr/bin/env python3
"""CDK app: a scheduled report job -- an EventBridge rate rule invoking a Lambda that writes a report
object to S3 and then mails it through SES.

Asset-free by construction: `Code.from_inline`, no `log_retention` and no `auto_delete_objects` (both
are custom resources built from file assets). The custom metric is a CloudWatch Logs METRIC FILTER
over the declared log group rather than a PutMetricData from the handler, so the telemetry is
produced by the log pipeline the workflow already depends on.

Context values (`cdk synth --context key=value`):
  variant           "ok" | "deny_s3". The broken variant keeps ses:SendEmail on the execution role
                    and removes the bucket's put grant, so the handler aborts before the send: the
                    denial names s3:PutObject, the bucket stays empty and no message id is ever
                    issued.
  bucket_name / fn_name / rule_name / alarm_name  explicit physical names, so the update/drift leg can
                    tell a modification from a replacement.
  report_prefix     the key prefix the handler writes under -- what the second apply changes, which is
                    an in-place Lambda modification with an observable at the destination.
  sender            an SES identity that is already verified in the target account. Verification needs
                    an out-of-band inbox click or a DNS record, so the check discovers one rather than
                    creating it.
  recipient         the SES mailbox simulator address, which needs no verification of its own.
  metric_namespace  the namespace the metric filter publishes into.
  stage_label       stamped into every report, so the drift leg can prove the NEW configuration ran.
  sink_queue_url /
  sink_queue_arn    an out-of-stack queue the handler reports into -- the witness that survives the
                    stack, which the teardown leg needs.
  alerts_queue_arn  an out-of-stack queue subscribed to the alarm topic.
"""
from aws_cdk import App, CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs

HANDLER_CODE = """
import json, os
import boto3

s3 = boto3.client('s3')
ses = boto3.client('ses')
sqs = boto3.client('sqs')

BUCKET = os.environ['BUCKET_NAME']
PREFIX = os.environ['REPORT_PREFIX']
SENDER = os.environ['SENDER']
RECIPIENT = os.environ['RECIPIENT']
SINK = os.environ['SINK_QUEUE_URL']
PROBE = os.environ['PROBE_ID']
LABEL = os.environ['STAGE_LABEL']


def _code(exc):
    return (getattr(exc, 'response', None) or {}).get('Error', {}).get('Code') or type(exc).__name__


def _report(doc):
    doc['probeId'] = PROBE
    doc['stageLabel'] = LABEL
    line = json.dumps(doc)
    print(line)
    try:
        sqs.send_message(QueueUrl=SINK, MessageBody=line)
    except Exception as exc:
        print(json.dumps({'event': 'sink_send_failed', 'errorCode': _code(exc)}))
    return doc


def handler(event, context):
    key = PREFIX + '/' + context.aws_request_id + '.json'
    body = json.dumps({'probeId': PROBE, 'stageLabel': LABEL, 'scheduledFor': event.get('time')})
    try:
        s3.put_object(
            Bucket=BUCKET, Key=key, Body=body.encode(), ContentType='application/json'
        )
    except Exception as exc:
        return _report({
            'event': 'report_failed',
            'stage': 's3_put_failed',
            'reportKey': key,
            'errorCode': _code(exc),
            'detail': str(exc)[:800],
        })
    try:
        resp = ses.send_email(
            Source=SENDER,
            Destination={'ToAddresses': [RECIPIENT]},
            Message={
                'Subject': {'Data': 'sim2real scheduled report ' + LABEL},
                'Body': {'Text': {'Data': body}},
            },
        )
    except Exception as exc:
        return _report({
            'event': 'report_failed',
            'stage': 'ses_send_failed',
            'reportKey': key,
            'errorCode': _code(exc),
            'detail': str(exc)[:800],
        })
    return _report({
        'event': 'report_sent',
        'reportKey': key,
        'sesMessageId': resp['MessageId'],
        'bytes': len(body),
    })
"""


class ScheduledReportStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        ctx = self.node.try_get_context
        variant = ctx("variant") or "ok"
        bucket_name = ctx("bucket_name")
        fn_name = ctx("fn_name")
        rule_name = ctx("rule_name")
        alarm_name = ctx("alarm_name")
        report_prefix = ctx("report_prefix") or "reports"
        metric_namespace = ctx("metric_namespace")
        stage_label = ctx("stage_label") or "v1"

        bucket = s3.Bucket(
            self,
            "Reports",
            bucket_name=bucket_name,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            # DESTROY, not the construct's RETAIN default: the teardown leg asserts the bucket is
            # gone. The check empties it first -- CloudFormation will not delete a non-empty bucket,
            # and `auto_delete_objects` is a custom resource from a file asset.
            removal_policy=RemovalPolicy.DESTROY,
        )

        log_group = logs.LogGroup(
            self,
            "FnLogs",
            log_group_name=f"/aws/lambda/{fn_name}",
            retention=logs.RetentionDays.ONE_DAY,
            removal_policy=RemovalPolicy.DESTROY,
        )
        fn = _lambda.Function(
            self,
            "Fn",
            function_name=fn_name,
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_inline(HANDLER_CODE),
            timeout=Duration.seconds(30),
            environment={
                "BUCKET_NAME": bucket_name,
                "REPORT_PREFIX": report_prefix,
                "SENDER": ctx("sender"),
                "RECIPIENT": ctx("recipient"),
                "SINK_QUEUE_URL": ctx("sink_queue_url"),
                "PROBE_ID": ctx("probe_id"),
                "STAGE_LABEL": stage_label,
            },
        )
        fn.node.add_dependency(log_group)
        # ses:SendEmail is granted in BOTH variants: the broken one must fail at the S3 write and
        # never reach the send, which is what makes "no message id was ever issued" an assertion
        # about the S3 refusal rather than about a second missing permission.
        fn.add_to_role_policy(
            iam.PolicyStatement(actions=["ses:SendEmail", "ses:SendRawEmail"], resources=["*"])
        )
        sqs.Queue.from_queue_arn(self, "Sink", ctx("sink_queue_arn")).grant_send_messages(fn)
        if variant == "ok":
            bucket.grant_put(fn)

        rule = events.Rule(
            self,
            "Schedule",
            rule_name=rule_name,
            schedule=events.Schedule.rate(Duration.minutes(1)),
        )
        rule.add_target(targets.LambdaFunction(fn))

        logs.MetricFilter(
            self,
            "SentFilter",
            log_group=log_group,
            # A literal term match on the structured line the handler prints on the success path.
            # `report_failed` does not contain it, so a denied run leaves the metric at nothing --
            # which is what the alarm leg grades.
            filter_pattern=logs.FilterPattern.literal('"report_sent"'),
            metric_namespace=metric_namespace,
            metric_name="ReportsSent",
            metric_value="1",
        )

        alert_topic = sns.Topic(self, "Alerts")
        sns.CfnSubscription(
            self,
            "AlertsToQueue",
            topic_arn=alert_topic.topic_arn,
            protocol="sqs",
            endpoint=ctx("alerts_queue_arn"),
        )
        alarm = cloudwatch.Alarm(
            self,
            "ReportsAlarm",
            alarm_name=alarm_name,
            metric=cloudwatch.Metric(
                namespace=metric_namespace,
                metric_name="ReportsSent",
                period=Duration.minutes(1),
                statistic="Sum",
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            # MISSING so the graded transition starts at INSUFFICIENT_DATA; NOT_BREACHING would
            # settle a never-fed alarm into OK first and the transition would never occur.
            treat_missing_data=cloudwatch.TreatMissingData.MISSING,
        )
        alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))

        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "ReportPrefix", value=report_prefix)
        CfnOutput(self, "FunctionName", value=fn.function_name)
        CfnOutput(self, "LogGroupName", value=log_group.log_group_name)
        CfnOutput(self, "RuleName", value=rule.rule_name)
        CfnOutput(self, "MetricNamespace", value=metric_namespace)
        CfnOutput(self, "AlarmName", value=alarm.alarm_name)
        CfnOutput(self, "AlertTopicArn", value=alert_topic.topic_arn)
        CfnOutput(self, "StageLabel", value=stage_label)
        CfnOutput(self, "Sender", value=ctx("sender"))
        CfnOutput(self, "Recipient", value=ctx("recipient"))
        CfnOutput(self, "ProbeId", value=ctx("probe_id"))


app = App()
ScheduledReportStack(app, "ScheduledReportStack")
app.synth()
