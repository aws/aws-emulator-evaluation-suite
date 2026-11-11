"""deregister-webhook-malformed-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deregister-webhook-malformed-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterWebhookWithThirdParty rejects a structurally malformed webhook name
    with ValidationException -- a distinct, earlier-in-the-pipeline boundary from
    WebhookNotFoundException, which is what a well-formed but nonexistent name gets."""
    cp = ctx.client("codepipeline")

    # webhookName must match ^[A-Za-z0-9.@\-_]+$ -- spaces and "!" violate the pattern.
    malformed_name = "bad name!"
    malformed_code, malformed_message = _error(
        lambda: cp.deregister_webhook_with_third_party(webhookName=malformed_name)
    )
    assert malformed_code == "ValidationException", f"unexpected code: {malformed_code}"
    assert malformed_message == (
        "1 validation error detected: Value at 'webhookName' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: [A-Za-z0-9.@\-_]+"
    ), f"unexpected message: {malformed_message!r}"

    # A well-formed name that simply doesn't correspond to any webhook takes a
    # different, later validation path: not-found, not a validation failure.
    missing_name = ctx.unique_name("sim2real-cp-nowebhook-")
    notfound_code, notfound_message = _error(
        lambda: cp.deregister_webhook_with_third_party(webhookName=missing_name)
    )
    assert notfound_code == "WebhookNotFoundException", f"unexpected code: {notfound_code}"
    assert notfound_message == "", f"unexpected message: {notfound_message!r}"

    # independent read: neither rejected call left any trace registerable via list_webhooks
    existing_names = {w["definition"]["name"] for w in cp.list_webhooks().get("webhooks", [])}
    assert malformed_name not in existing_names, f"malformed name leaked into list_webhooks: {existing_names}"
    assert missing_name not in existing_names, f"missing name leaked into list_webhooks: {existing_names}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
