"""create-email-contact-with-tags-at-creation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-contact-with-tags-at-creation"
GROUP = "tags"
SERVICES = ["notificationscontacts"]


def _nc_client(ctx):
    """notifications-contacts is a global service pinned to us-east-1. Calls retry the
    service's intermittent "Credential should be scoped to a valid region"
    InvalidSignatureException, an edge-routing blip that succeeds moments later. Each
    attempt builds a fresh client (and connection), so a pinned bad connection can't keep
    re-hitting the same route."""
    import time

    from botocore.config import Config

    def _build():
        return ctx.client(
            "notificationscontacts",
            region="us-east-1",
            config=Config(retries={"max_attempts": 8, "mode": "standard"}),
        )

    max_attempts, backoff_s = 40, 5

    class _RetryingNcClient:
        def __getattr__(self, name):
            def _call(*args, **kwargs):
                for attempt in range(max_attempts):
                    client = _build()
                    try:
                        return getattr(client, name)(*args, **kwargs)
                    except ClientError as exc:
                        if (
                            "scoped to a valid region" not in str(exc)
                            or attempt == max_attempts - 1
                        ):
                            raise
                        time.sleep(backoff_s)

            return _call

    return _RetryingNcClient()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed to CreateEmailContact are returned unchanged by ListTagsForResource."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-createtag-")
    tags = {"Origin": "create-call"}
    arn = client.create_email_contact(
        name=name, emailAddress=f"{name}@example.com", tags=tags
    )["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))

    fetched = client.list_tags_for_resource(arn=arn)["tags"]
    assert fetched == tags, f"expected {tags}, got {fetched}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
