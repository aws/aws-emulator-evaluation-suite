"""One stack holding one SQS queue, whose construct id and queue-name suffix are both overridable
so a run can ask for a pure rename or a rename combined with a property change."""
import aws_cdk as cdk
import aws_cdk.aws_sqs as sqs
from constructs import Construct

app = cdk.App()
stack_name = app.node.try_get_context("stack_name")
construct_id = app.node.try_get_context("construct_id")
suffix = app.node.try_get_context("suffix")


class QueueStack(cdk.Stack):
    def __init__(self, scope: Construct, cid: str, **kwargs) -> None:
        super().__init__(scope, cid, **kwargs)
        sqs.Queue(self, construct_id, queue_name=f"{cid}-{suffix}-q")


QueueStack(app, stack_name)
app.synth()
