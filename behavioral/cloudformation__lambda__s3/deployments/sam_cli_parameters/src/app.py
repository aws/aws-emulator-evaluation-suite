import os


def handler(event, context):
    return {"greeting": os.environ["GREETING"], "stage": os.environ["STAGE"]}
