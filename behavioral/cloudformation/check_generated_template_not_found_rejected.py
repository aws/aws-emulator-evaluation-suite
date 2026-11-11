"""generated-template-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-template-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """Get/Describe/Update/DeleteGeneratedTemplate on a never-created name return
    GeneratedTemplateNotFound, after the same four calls succeed on a real generated template."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")

    real_name = ctx.unique_name("sim2real-gt-real-")
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-gt-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sns.delete_topic(TopicArn=topic_arn)))

    cfn.create_generated_template(
        GeneratedTemplateName=real_name,
        Resources=[
            {
                "ResourceType": "AWS::SNS::Topic",
                "ResourceIdentifier": {"TopicArn": topic_arn},
                "LogicalResourceId": "Topic",
            }
        ],
    )
    state = {"name": real_name}
    ctx.on_cleanup(
        lambda: _swallow(lambda: cfn.delete_generated_template(GeneratedTemplateName=state["name"]))
        if state["name"]
        else None
    )
    _poll_status(cfn, real_name, timeout_s=180)

    got = cfn.get_generated_template(GeneratedTemplateName=real_name)
    assert got.get("Status") == "COMPLETE", f"positive control GetGeneratedTemplate: {got!r}"
    described = cfn.describe_generated_template(GeneratedTemplateName=real_name)
    assert described.get("Status") == "COMPLETE", f"positive control DescribeGeneratedTemplate: {described!r}"

    renamed_name = ctx.unique_name("sim2real-gt-real-v2-")
    cfn.update_generated_template(GeneratedTemplateName=real_name, NewGeneratedTemplateName=renamed_name)
    state["name"] = renamed_name
    _poll_status(cfn, renamed_name, timeout_s=180)

    cfn.delete_generated_template(GeneratedTemplateName=renamed_name)
    state["name"] = None

    # AWS returns the wire code "GeneratedTemplateNotFound", not the modeled shape name
    # GeneratedTemplateNotFoundException.
    bogus_name = ctx.unique_name("sim2real-gt-bogus-")
    checks = [
        ("DeleteGeneratedTemplate", lambda: cfn.delete_generated_template(GeneratedTemplateName=bogus_name)),
        ("DescribeGeneratedTemplate", lambda: cfn.describe_generated_template(GeneratedTemplateName=bogus_name)),
        ("GetGeneratedTemplate", lambda: cfn.get_generated_template(GeneratedTemplateName=bogus_name)),
        ("UpdateGeneratedTemplate", lambda: cfn.update_generated_template(GeneratedTemplateName=bogus_name)),
    ]
    for label, fn in checks:
        error = _client_error(fn)
        assert error.get("Code") == "GeneratedTemplateNotFound", (
            f"{label} returned {error.get('Code')!r}, expected GeneratedTemplateNotFound"
        )
        message = error.get("Message", "")
        # The message ends in a per-call request id: grade its stable prefix and suffix.
        assert message.startswith(f"Template with arn {bogus_name} does not exist (Service: ") and message.endswith(
            "; Proxy: null)"
        ), message


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("GeneratedTemplateNotFound", "NotFound"):
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
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

    status = _poll_until(
        _status, lambda s: s.endswith("COMPLETE") or s.endswith("FAILED"), timeout_s=timeout_s, interval_s=interval_s
    )
    assert status == "COMPLETE", f"positive control generated template {name!r} ended in {status}"
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
