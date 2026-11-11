"""create-email-contact-invalid-email-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-contact-invalid-email-rejected"
GROUP = "overly-permissive"
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


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected ValidationException for the malformed email, but the call SUCCEEDED: {result!r}"
    )


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEmailContact with emailAddress 'not-an-email' fails with ValidationException and the exact
    pattern message and lists no such contact; a valid address creates a contact that reads back by name."""
    client = _nc_client(ctx)
    bad_name = ctx.unique_name("sim2real-nc-badmail-")

    code, message = _error(
        lambda: client.create_email_contact(name=bad_name, emailAddress="not-an-email")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'emailAddress' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: (.+)@(.+)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no contact with that name exists
    names_after_rejection = _names_in_list(client)
    assert bad_name not in names_after_rejection, (
        f"rejected contact {bad_name!r} should not appear in list_email_contacts, "
        f"but it was found among {sorted(names_after_rejection)!r}"
    )

    # positive control in the same file: a valid create still succeeds
    good_name = ctx.unique_name("sim2real-nc-goodmail-")
    arn = client.create_email_contact(name=good_name, emailAddress=f"{good_name}@example.com")[
        "arn"
    ]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))
    got_name = client.get_email_contact(arn=arn)["emailContact"]["name"]
    assert got_name == good_name, (
        f"expected the positive-control contact {good_name!r} to round-trip, got {got_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
