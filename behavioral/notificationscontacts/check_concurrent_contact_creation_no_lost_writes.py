"""concurrent-contact-creation-no-lost-writes."""
from __future__ import annotations

from botocore.exceptions import ClientError

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-contact-creation-no-lost-writes"
GROUP = "concurrency"
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
    """Five concurrent CreateEmailContact calls with distinct names return five distinct ARNs, and
    ListEmailContacts lists every one of the names."""
    client = _nc_client(ctx)
    n = 5
    names = [ctx.unique_name(f"sim2real-nc-conc{i}-") for i in range(n)]

    def _create(name: str) -> str:
        return client.create_email_contact(
            name=name, emailAddress=f"{name}@example.com", tags={"Team": "sim2real"}
        )["arn"]

    with ThreadPoolExecutor(max_workers=n) as pool:
        arns = list(pool.map(_create, names))

    for arn in arns:
        ctx.on_cleanup(lambda arn=arn: client.delete_email_contact(arn=arn))

    assert len(set(arns)) == n, "concurrent creates did not yield N distinct ARNs"

    seen_names: set[str] = set()
    next_token = None
    while True:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_email_contacts(**kwargs)
        seen_names.update(c["name"] for c in resp.get("emailContacts", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break

    for name in names:
        assert name in seen_names, f"{name!r} lost under concurrent creation"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
