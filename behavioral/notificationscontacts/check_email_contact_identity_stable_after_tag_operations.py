"""email-contact-identity-stable-after-tag-operations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "email-contact-identity-stable-after-tag-operations"
GROUP = "state"
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
    """TagResource then UntagResource on a contact leave its arn, name, address and creationTime unchanged
    on GetEmailContact."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-identity-")
    email = f"{name}@example.com"
    arn = client.create_email_contact(name=name, emailAddress=email)["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))

    before = client.get_email_contact(arn=arn)["emailContact"]

    client.tag_resource(arn=arn, tags={"Marker": "before-untag"})
    client.untag_resource(arn=arn, tagKeys=["Marker"])

    after = client.get_email_contact(arn=arn)["emailContact"]

    assert after["arn"] == before["arn"], (
        f"arn mutated by tag/untag: before={before['arn']!r} after={after['arn']!r}"
    )
    assert after["name"] == before["name"], (
        f"name mutated by tag/untag: before={before['name']!r} after={after['name']!r}"
    )
    assert after["address"] == before["address"], (
        f"address mutated by tag/untag: before={before['address']!r} after={after['address']!r}"
    )
    assert after["creationTime"] == before["creationTime"], (
        f"creationTime mutated by tag/untag: before={before['creationTime']!r} "
        f"after={after['creationTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
