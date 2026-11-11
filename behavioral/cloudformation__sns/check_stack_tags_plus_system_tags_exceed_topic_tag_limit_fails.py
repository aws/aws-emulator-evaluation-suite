"""stack-tags-plus-system-tags-exceed-topic-tag-limit-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-tags-plus-system-tags-exceed-topic-tag-limit-fails"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

_SYSTEM_TAG_KEYS = (
    "aws:cloudformation:stack-name",
    "aws:cloudformation:stack-id",
    "aws:cloudformation:logical-id",
)


def _template(topic_name: str) -> str:
    return json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name}},
        },
    })


def _wait_terminal(cf, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} terminal not met within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id, timeout_s=timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended in {status!r}, expected DELETE_COMPLETE")


def _resource_status_reason(cf, stack_id: str, logical_id: str) -> str:
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    for page in pages:
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == logical_id and event["ResourceStatus"] == "CREATE_FAILED":
                return event["ResourceStatusReason"]
    raise AssertionError(f"no CREATE_FAILED event found for {logical_id!r} in stack {stack_id!r}")


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """CloudFormation adds 3 system tags to a taggable topic on top of the stack's own Tags;
    49 stack Tags (52 total) exceed SNS's own 50-tag-per-resource limit and CREATE_FAILED carries
    SNS's exact reason, while 47 stack Tags (50 total) deploy.
    """
    cf = ctx.client("cloudformation")
    sns = ctx.client("sns")

    ok_name = ctx.unique_name("sim2real-behav-snscap-ok-")
    ok_topic = ctx.unique_name("sim2real-behav-snscap-okt-")
    ok_tags = [{"Key": f"sim2real-k{i}", "Value": "v"} for i in range(47)]
    ok_stack_id = cf.create_stack(
        StackName=ok_name, TemplateBody=_template(ok_topic), Tags=ok_tags
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, ok_stack_id))
    status = _wait_terminal(cf, ok_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"positive control: stack {ok_name!r} with 47 stack Tags (50 with system tags) ended in "
        f"{status!r}, expected CREATE_COMPLETE"
    )
    topic_arn = cf.describe_stack_resource(StackName=ok_stack_id, LogicalResourceId="Topic")[
        "StackResourceDetail"]["PhysicalResourceId"]
    ok_topic_tags = {t["Key"]: t["Value"] for t in sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]}
    assert len(ok_topic_tags) == 50, f"topic carries {len(ok_topic_tags)} tags, expected exactly 50"
    present = [k for k in _SYSTEM_TAG_KEYS if k in ok_topic_tags]
    assert sorted(present) == sorted(_SYSTEM_TAG_KEYS), (
        f"AWS::SNS::Topic's schema says CloudFormation applies its system tags, but only "
        f"{present!r} appeared; all tags: {ok_topic_tags!r}"
    )

    over_name = ctx.unique_name("sim2real-behav-snscap-over-")
    over_topic = ctx.unique_name("sim2real-behav-snscap-overt-")
    over_tags = [{"Key": f"sim2real-k{i}", "Value": "v"} for i in range(49)]
    over_stack_id = cf.create_stack(
        StackName=over_name, TemplateBody=_template(over_topic), Tags=over_tags
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, over_stack_id))
    status = _wait_terminal(cf, over_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {over_name!r} with 49 stack Tags (52 with system tags) ended in {status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )
    reason = _resource_status_reason(cf, over_stack_id, "Topic")
    expected = (
        'Resource handler returned message: "Could not complete request: tag quota of per '
        'resource exceeded (Service: Sns, Status Code: 400, Request ID: {request_id}) (SDK '
        'Attempt Count: {attempts})" (RequestToken: {request_token}, HandlerErrorCode: GeneralServiceException)'
    )
    masked = _mask_ids(reason)
    assert masked == expected, masked

    code, msg = _error(
        lambda: sns.get_topic_attributes(
            TopicArn=f"arn:aws:sns:{ctx.region}:{ctx.account}:{over_topic}"
        )
    )
    assert code == "NotFound", (
        f"the rejected CreateStack must never have created the topic; GetTopicAttributes on "
        f"{over_topic!r} returned {code!r}"
    )
    assert msg == "Topic does not exist", msg


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _mask_ids(reason: str) -> str:
    """Replace the Request ID, RequestToken and SDK attempt count with placeholders."""
    import re
    reason = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: {request_id}", reason)
    reason = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: {attempts}", reason)
    reason = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: {request_token}", reason)
    return reason


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
