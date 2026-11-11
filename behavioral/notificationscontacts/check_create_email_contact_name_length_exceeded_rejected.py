"""create-email-contact-name-length-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-contact-name-length-exceeded-rejected"
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
        f"expected ValidationException for the over-long name, but the call SUCCEEDED: {result!r}"
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
    """CreateEmailContact with a name over 64 characters fails with ValidationException and the exact message
    and lists no such contact; a name of exactly 64 characters is created and reads back."""
    client = _nc_client(ctx)
    too_long_name = "a" * 65  # max length is 64
    email = f"{ctx.unique_name('sim2real-nc-toolong-')}@example.com"

    code, message = _error(
        lambda: client.create_email_contact(name=too_long_name, emailAddress=email)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must have length less than or equal to 64"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no such name landed in the account
    names_after_rejection = _names_in_list(client)
    assert too_long_name not in names_after_rejection, (
        f"rejected name {too_long_name!r} should not appear in list_email_contacts, "
        f"but it was found among {sorted(names_after_rejection)!r}"
    )

    # positive control in the same file: a name at the exact 64-char boundary is accepted —
    # pad the unique prefix out to exactly 64 chars so this genuinely exercises the boundary,
    # not just some arbitrary short name.
    ok_prefix = ctx.unique_name("sim2real-nc-ok64-")
    assert len(ok_prefix) <= 64, f"unique prefix {ok_prefix!r} already exceeds 64 chars"
    ok_name = ok_prefix + ("0" * (64 - len(ok_prefix)))
    assert len(ok_name) == 64, f"boundary control name must be exactly 64 chars, got {len(ok_name)}"
    ok_email = f"{ctx.unique_name('sim2real-nc-ok64-')}@example.com"
    arn = client.create_email_contact(name=ok_name, emailAddress=ok_email)["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))
    got_name = client.get_email_contact(arn=arn)["emailContact"]["name"]
    assert got_name == ok_name, f"expected the 64-char name {ok_name!r} to round-trip, got {got_name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
