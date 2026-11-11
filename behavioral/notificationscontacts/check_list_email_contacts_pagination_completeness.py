"""list-email-contacts-pagination-completeness."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-email-contacts-pagination-completeness"
GROUP = "data-plane"
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
    """Paging ListEmailContacts with maxResults=1 lists each of three created contacts exactly once."""
    client = _nc_client(ctx)

    created = []
    for _ in range(3):
        name = ctx.unique_name("sim2real-nc-page-")
        arn = client.create_email_contact(
            name=name, emailAddress=f"{name}@example.com", tags={"sim2real": CHECK}
        )["arn"]
        created.append((name, arn))
    for _, arn in created:
        ctx.on_cleanup(lambda arn=arn: client.delete_email_contact(arn=arn))

    seen_names = []
    next_token = None
    for _ in range(500):  # hard bound on pages, well beyond what 3+preexisting contacts need
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_email_contacts(**kwargs)
        for c in resp.get("emailContacts", []):
            seen_names.append(c["name"])
        next_token = resp.get("nextToken")
        if not next_token:
            break

    created_names = [n for n, _ in created]
    for name in created_names:
        assert seen_names.count(name) == 1, f"{name!r} appeared {seen_names.count(name)} times across pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
