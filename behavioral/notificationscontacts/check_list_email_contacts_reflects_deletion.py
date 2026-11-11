"""list-email-contacts-reflects-deletion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-email-contacts-reflects-deletion"
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


def _delete_ignoring_not_found(client, arn: str) -> None:
    try:
        client.delete_email_contact(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _names_in_list(client) -> set[str]:
    names: set[str] = set()
    next_token = None
    while True:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_email_contacts(**kwargs)
        names.update(c["name"] for c in resp.get("emailContacts", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return names


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created contact is listed by ListEmailContacts and is gone from it within 30 s of
    DeleteEmailContact."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-list-")
    arn = client.create_email_contact(
        name=name, emailAddress=f"{name}@example.com", tags={"sim2real": "true"}
    )["arn"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(client, arn))

    assert name in _names_in_list(client), "newly created contact missing from ListEmailContacts"

    client.delete_email_contact(arn=arn)

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if name not in _names_in_list(client):
            return
        time.sleep(1.0)
    raise AssertionError("deleted contact still present in ListEmailContacts after 30s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
