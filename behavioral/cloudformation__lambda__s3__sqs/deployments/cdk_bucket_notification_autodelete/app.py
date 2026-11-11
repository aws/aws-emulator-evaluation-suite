"""cdk-bucket-notification-autodelete - an auto_delete_objects Bucket with an SQS put notification."""
import os

import aws_cdk as cdk
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_notifications as s3n
from aws_cdk import aws_sqs as sqs


class BucketQueueStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        bucket = s3.Bucket(
            self, "Bucket", auto_delete_objects=True, removal_policy=cdk.RemovalPolicy.DESTROY
        )
        queue = sqs.Queue(self, "Queue", removal_policy=cdk.RemovalPolicy.DESTROY)
        bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.SqsDestination(queue),
            s3.NotificationKeyFilter(prefix="watched/"),
        )
        cdk.CfnOutput(self, "BucketName", value=bucket.bucket_name)
        cdk.CfnOutput(self, "QueueUrl", value=queue.queue_url)
        cdk.CfnOutput(self, "QueueArn", value=queue.queue_arn)
        cdk.Tags.of(self).add("sim2real", os.environ["CHECK_ID"])


app = cdk.App()
BucketQueueStack(
    app, os.environ["STACK_NAME"],
    synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
    env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]),
)
app.synth()
