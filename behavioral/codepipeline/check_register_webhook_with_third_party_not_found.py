"""register-webhook-with-third-party-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-webhook-with-third-party-not-found"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterWebhookWithThirdParty rejects a structurally malformed webhook name
    with ValidationException -- a distinct, earlier-in-the-pipeline boundary from
    WebhookNotFoundException, which is what a well-formed but nonexistent name gets."""
    ev = ctx.client("codepipeline")

    # webhookName must match ^[A-Za-z0-9.@\-_]+$ -- spaces and "!" violate the pattern.
    malformed = _error(
        lambda: ev.register_webhook_with_third_party(webhookName="bad name!")
    )
    assert malformed.get("Code") == "ValidationException", f"unexpected error: {malformed!r}"
    expected_message = (
        "1 validation error detected: Value at 'webhookName' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: [A-Za-z0-9.@\-_]+"
    )
    assert malformed.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {malformed.get('Message')!r}"
    )

    # A well-formed name that simply doesn't correspond to any webhook takes a
    # different, later validation path: not-found, not a validation failure.
    missing_name = ctx.unique_name("sim2real-behav-absent-webhook-")
    notfound = _error(
        lambda: ev.register_webhook_with_third_party(webhookName=missing_name)
    )
    assert notfound.get("Code") == "WebhookNotFoundException", f"unexpected error: {notfound!r}"
    # AWS returns this refusal with an empty message.
    expected_message = ""
    assert notfound.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {notfound.get('Message')!r}"
    )


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
