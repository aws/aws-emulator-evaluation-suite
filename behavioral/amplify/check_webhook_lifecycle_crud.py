"""webhook-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "webhook-lifecycle-crud"
GROUP = "lifecycle"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A webhook can be created, read, listed, updated, and deleted; after deletion it 404s
    both on read and on a further mutation."""
    amplify = ctx.client("amplify")
    app_id = _create_app(ctx)

    branch_name = ctx.unique_name("branch-")
    amplify.create_branch(appId=app_id, branchName=branch_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_branch(appId=app_id, branchName=branch_name)))

    webhook = amplify.create_webhook(appId=app_id, branchName=branch_name, description="initial")["webhook"]
    webhook_id = webhook["webhookId"]
    assert webhook["webhookUrl"].startswith("https://"), f"expected https webhookUrl, got {webhook['webhookUrl']!r}"
    assert webhook["branchName"] == branch_name, f"expected branchName={branch_name!r}, got {webhook['branchName']!r}"

    fetched = amplify.get_webhook(webhookId=webhook_id)["webhook"]
    assert fetched["webhookId"] == webhook_id, f"expected webhookId={webhook_id!r}, got {fetched['webhookId']!r}"
    assert fetched["description"] == "initial", f"expected description='initial', got {fetched['description']!r}"

    listed = amplify.list_webhooks(appId=app_id)["webhooks"]
    assert any(w["webhookId"] == webhook_id for w in listed), f"webhook {webhook_id} missing from list_webhooks"

    amplify.update_webhook(webhookId=webhook_id, description="updated")
    refetched = amplify.get_webhook(webhookId=webhook_id)["webhook"]
    assert refetched["description"] == "updated", f"expected description='updated', got {refetched['description']!r}"

    amplify.delete_webhook(webhookId=webhook_id)

    gone = ("NotFoundException", f"Webhook {webhook_id} not found.")
    read_err = _client_error(lambda: amplify.get_webhook(webhookId=webhook_id))
    assert read_err == gone, f"expected {gone} on read of deleted webhook, got {read_err}"

    mutate_err = _client_error(lambda: amplify.update_webhook(webhookId=webhook_id, description="post-delete"))
    assert mutate_err == gone, f"expected {gone} mutating deleted webhook, got {mutate_err}"


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises, so an emulator
    accepting a call real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


def _create_app(ctx) -> str:
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    app = amplify.create_app(name=name, tags={"sim2real": CHECK})["app"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
