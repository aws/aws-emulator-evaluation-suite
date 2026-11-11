"""get-email-contact-matches-created-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

import datetime

from behavioral_harness import tags

CHECK = "get-email-contact-matches-created-fields"
GROUP = "control-plane"
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
    """GetEmailContact returns the created arn, name and address with status inactive, and a creationTime
    inside the create call's time window that equals updateTime."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-")
    email = f"{name}@example.com"
    before = datetime.datetime.now(datetime.timezone.utc)
    arn = client.create_email_contact(
        name=name, emailAddress=email, tags={"sim2real-audit": name}
    )["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))

    contact = client.get_email_contact(arn=arn)["emailContact"]
    after = datetime.datetime.now(datetime.timezone.utc)
    assert contact["arn"] == arn, f"expected arn {arn!r}, got {contact['arn']!r}"
    assert contact["name"] == name, f"expected name {name!r}, got {contact['name']!r}"
    assert contact["address"] == email, f"expected address {email!r}, got {contact['address']!r}"
    assert contact["status"] == "inactive", (
        f"expected a freshly created contact to start 'inactive', got {contact['status']!r}"
    )
    creation_time = contact["creationTime"]
    update_time = contact["updateTime"]
    assert isinstance(creation_time, datetime.datetime), (
        f"expected creationTime to be a datetime, got {creation_time!r}"
    )
    assert isinstance(update_time, datetime.datetime), (
        f"expected updateTime to be a datetime, got {update_time!r}"
    )
    assert before <= creation_time <= after, (
        f"expected creationTime {creation_time!r} within the create-call window "
        f"[{before!r}, {after!r}]"
    )
    assert creation_time == update_time, (
        f"expected creationTime == updateTime for a contact with no update since creation, "
        f"got {creation_time!r} != {update_time!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
