"""generated-template-retention-window-expiry."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generated-template-retention-window-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:cfn-generated-template")
def run(ctx) -> None:
    """A generated template reaches COMPLETE and is visible via Describe/ListGeneratedTemplates;
    once deleted it is gone from both and reads/updates fail with GeneratedTemplateNotFound."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-gentpl-")

    create = cfn.create_generated_template(GeneratedTemplateName=name)
    template_id = create["GeneratedTemplateId"]
    ctx.on_cleanup(lambda: _delete_if_present(cfn, name))

    status = _poll_generated_template_terminal(cfn, name, timeout_s=180)
    assert status == "COMPLETE", f"expected terminal status COMPLETE, got {status!r}"

    described = cfn.describe_generated_template(GeneratedTemplateName=name)
    assert described["GeneratedTemplateId"] == template_id, (
        f"expected GeneratedTemplateId {template_id!r}, got {described['GeneratedTemplateId']!r}"
    )
    assert described["GeneratedTemplateName"] == name, (
        f"expected GeneratedTemplateName {name!r}, got {described['GeneratedTemplateName']!r}"
    )
    assert described["Status"] == "COMPLETE", f"expected Status COMPLETE, got {described['Status']!r}"

    summary = _find_summary(cfn, name)
    assert summary is not None, "newly-created generated template missing from ListGeneratedTemplates"
    assert summary["GeneratedTemplateId"] == template_id, (
        f"expected summary GeneratedTemplateId {template_id!r}, got {summary['GeneratedTemplateId']!r}"
    )
    assert summary["Status"] == "COMPLETE", f"expected summary Status COMPLETE, got {summary['Status']!r}"

    # AWS documents a per-account count quota but no retention TTL for generated templates,
    # so removal is exercised by explicit deletion rather than by waiting for expiry.
    cfn.delete_generated_template(GeneratedTemplateName=name)
    _wait_for_generated_template_gone(cfn, name, timeout_s=120)

    # The effect of deletion is absent-from-both, not just a 200 on the delete call.
    assert _find_summary(cfn, name) is None, f"{name} still present in ListGeneratedTemplates after delete"
    code, message = _error_code(lambda: cfn.describe_generated_template(GeneratedTemplateName=name))
    assert code == "GeneratedTemplateNotFound", f"expected GeneratedTemplateNotFound, got {code!r}"
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message

    # A mutation on the deleted name must also fail, not just a read.
    update_code, message = _error_code(
        lambda: cfn.update_generated_template(GeneratedTemplateName=name, NewGeneratedTemplateName=name + "-renamed")
    )
    assert update_code == "GeneratedTemplateNotFound", (
        f"expected UpdateGeneratedTemplate on deleted {name!r} to fail with GeneratedTemplateNotFound, got {update_code!r}"
    )
    # The message ends in a per-call request id: grade its stable prefix and suffix.
    assert message.startswith(f"Template with arn {name} does not exist (Service: ") and message.endswith(
        "; Proxy: null)"
    ), message



def _error_code(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_generated_template_terminal(cfn, name, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_generated_template(GeneratedTemplateName=name)
        last = resp["Status"]
        if last in ("COMPLETE", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"generated template {name} never reached a terminal status, last={last}")


def _find_summary(cfn, name):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = cfn.list_generated_templates(**kwargs)
        for summary in page.get("Summaries", []):
            if summary.get("GeneratedTemplateName") == name:
                return summary
        next_token = page.get("NextToken")
        if not next_token:
            return None


def _wait_for_generated_template_gone(cfn, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            cfn.describe_generated_template(GeneratedTemplateName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "GeneratedTemplateNotFound":
                return
        time.sleep(interval_s)
    raise AssertionError(f"generated template {name} was never removed after delete")


def _delete_if_present(cfn, name) -> None:
    try:
        cfn.delete_generated_template(GeneratedTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "GeneratedTemplateNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
