"""generated-template-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-template-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """A generated template moves through CREATE_PENDING/IN_PROGRESS/COMPLETE, is
    retrievable and updatable, and disappears after delete."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-gentpl-")
    state = {"name": name}

    def _cleanup():
        if state["name"] is None:
            return
        try:
            cfn.delete_generated_template(GeneratedTemplateName=state["name"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # A generated template with zero included resources has no TemplateBody and
    # GetGeneratedTemplate reports it as "not found"; seed the template with a
    # real, existing resource so the generated template actually has content.
    topic_name = ctx.unique_name("sim2real-gentpl-topic-")
    topic_arn = sns.create_topic(Name=topic_name, Tags=[{"Key": "sim2real", "Value": name}])["TopicArn"]
    ctx.on_cleanup(lambda: _safe_delete_topic(sns, topic_arn))

    created = cfn.create_generated_template(
        GeneratedTemplateName=name,
        Resources=[
            {
                "ResourceType": "AWS::SNS::Topic",
                "ResourceIdentifier": {"TopicArn": topic_arn},
                "LogicalResourceId": "Topic",
            }
        ],
    )
    assert created["GeneratedTemplateId"], f"CreateGeneratedTemplate returned no id: {created!r}"

    status = _poll_status(cfn, name, timeout_s=180)
    assert status == "COMPLETE", f"generated template ended in status {status}"

    described = cfn.describe_generated_template(GeneratedTemplateName=name)
    assert described["Resources"][0]["ResourceIdentifier"]["TopicArn"] == topic_arn, described["Resources"]

    got = cfn.get_generated_template(GeneratedTemplateName=name)
    assert got["Status"] == "COMPLETE", f"expected COMPLETE, got {got['Status']}"
    assert topic_name in got["TemplateBody"], f"seeded topic name {topic_name} not reflected in TemplateBody: {got['TemplateBody']!r}"

    summaries = cfn.list_generated_templates()["Summaries"]
    assert any(s["GeneratedTemplateName"] == name for s in summaries), summaries

    new_name = ctx.unique_name("sim2real-gentpl-v2-")
    cfn.update_generated_template(GeneratedTemplateName=name, NewGeneratedTemplateName=new_name)
    state["name"] = new_name

    status2 = _poll_status(cfn, new_name, timeout_s=180)
    assert status2 == "COMPLETE", f"renamed generated template ended in status {status2}"

    describe_old = _expect_error(
        lambda: cfn.describe_generated_template(GeneratedTemplateName=name),
        timeout_s=120,
        interval_s=5,
    ).response["Error"]
    describe_old_code, message = describe_old["Code"], describe_old.get("Message", "")
    assert describe_old_code == "GeneratedTemplateNotFound", describe_old_code
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    cfn.delete_generated_template(GeneratedTemplateName=new_name)

    final = _expect_error(
        lambda: cfn.describe_generated_template(GeneratedTemplateName=new_name),
        timeout_s=120,
        interval_s=5,
    ).response["Error"]
    final_code, message = final["Code"], final.get("Message", "")
    assert final_code == "GeneratedTemplateNotFound", final_code
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {new_name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message
    state["name"] = None


def _expect_error(fn, *, timeout_s=0.0, interval_s=5.0):
    """Call fn() until it raises a ClientError and return that error. A call that keeps
    SUCCEEDING past timeout_s raises AssertionError (timeout_s=0 means one attempt)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected a ClientError, but the call kept SUCCEEDING for {timeout_s}s; last={result!r}"
            )
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _poll_status(cfn, name, timeout_s=180.0, interval_s=5.0):
    def _status():
        return cfn.describe_generated_template(GeneratedTemplateName=name)["Status"]

    return _poll_until(_status, lambda s: s.endswith("COMPLETE") or s.endswith("FAILED"), timeout_s=timeout_s, interval_s=interval_s)


def _safe_delete_topic(sns, topic_arn) -> None:
    try:
        sns.delete_topic(TopicArn=topic_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
