"""webhook-targeting-absent-pipeline-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webhook-targeting-absent-pipeline-lifecycle"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message); an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, (
            f"expected code {code!r}, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected ({code!r}, {message!r}) to be raised, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A webhook whose targetPipeline names no pipeline is accepted, listed with its ARN
    and definition until DeleteWebhook removes it, a repeat delete still answers 200, and
    DeregisterWebhookWithThirdParty on the deleted name is refused WebhookNotFoundException."""
    cp = ctx.client("codepipeline")

    webhook_name = ctx.unique_name("sim2real-behav-cp-wh-")
    absent_pipeline = ctx.unique_name("sim2real-behav-cp-pl-absent-")
    webhook_def = {
        "name": webhook_name,
        "targetPipeline": absent_pipeline,
        "targetAction": "Source",
        "filters": [{"jsonPath": "$.ref", "matchEquals": "refs/heads/main"}],
        "authentication": "UNAUTHENTICATED",
        "authenticationConfiguration": {},
    }
    created = cp.put_webhook(webhook=webhook_def)["webhook"]
    ctx.on_cleanup(lambda: cp.delete_webhook(name=webhook_name))
    webhook_arn = created["arn"]
    assert created["definition"] == webhook_def, f"PutWebhook echoed {created['definition']!r}"

    # A sibling webhook that is never deleted is the control: it stays listed and is not
    # refused with WebhookNotFoundException, isolating what the deleted name triggers.
    sibling_name = ctx.unique_name("sim2real-behav-cp-wh-sibling-")
    sibling_def = dict(webhook_def, name=sibling_name)
    sibling = cp.put_webhook(webhook=sibling_def)["webhook"]
    ctx.on_cleanup(lambda: cp.delete_webhook(name=sibling_name))
    sibling_arn = sibling["arn"]

    listed = {w["definition"]["name"]: w for w in cp.list_webhooks().get("webhooks", [])}
    assert webhook_name in listed, f"webhook missing from ListWebhooks: {sorted(listed)}"
    assert listed[webhook_name]["arn"] == webhook_arn, (
        f"listed arn {listed[webhook_name]['arn']!r} != created arn {webhook_arn!r}"
    )
    assert listed[webhook_name]["definition"] == webhook_def, (
        f"listed definition {listed[webhook_name]['definition']!r} != {webhook_def!r}"
    )

    deleted = cp.delete_webhook(name=webhook_name)
    assert deleted["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"first delete status {deleted['ResponseMetadata']['HTTPStatusCode']}"
    )

    listed_after = {w["definition"]["name"]: w for w in cp.list_webhooks().get("webhooks", [])}
    assert webhook_name not in listed_after, f"deleted webhook still listed: {sorted(listed_after)}"
    assert sibling_name in listed_after, f"sibling webhook missing after delete: {sorted(listed_after)}"
    assert listed_after[sibling_name]["arn"] == sibling_arn, (
        f"sibling arn {listed_after[sibling_name]['arn']!r} != created arn {sibling_arn!r}"
    )

    repeated = cp.delete_webhook(name=webhook_name)
    assert repeated["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"repeat delete status {repeated['ResponseMetadata']['HTTPStatusCode']}"
    )

    _WEBHOOK_NOT_FOUND = ("WebhookNotFoundException", "")
    expect_error(
        lambda: cp.deregister_webhook_with_third_party(webhookName=webhook_name),
        *_WEBHOOK_NOT_FOUND,
    )

    _SIBLING_AUTH_MISMATCH = (
        "ValidationException",
        f"Webhook {sibling_name} must be configured with GITHUB_HMAC authentication "
        "type. Type is UNAUTHENTICATED.",
    )
    expect_error(
        lambda: cp.deregister_webhook_with_third_party(webhookName=sibling_name),
        *_SIBLING_AUTH_MISMATCH,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
