"""delete-nonexistent-contact-not-found."""
from __future__ import annotations

import re

import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-contact-not-found"
GROUP = "error-semantics"
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
    """Call fn(); return its botocore error (code, message without the per-request suffix). An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], _without_request_suffix(err.get("Message", ""))
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


_REQUEST_SUFFIX = re.compile(
    r" \(Service: [A-Za-z0-9]+, Status Code: \d+, Request ID: [0-9a-fA-F-]+\)"
    r"( \(SDK Attempt Count: \d+\))?$"
)


def _without_request_suffix(message: str) -> str:
    """The message minus its per-request "(Service: ..., Request ID: ...) (SDK Attempt Count: n)"
    suffix, which is the only part that differs between calls."""
    return _REQUEST_SUFFIX.sub("", message or "")


def _bogus_contact_arn(account_id: str) -> str:
    # syntactically valid emailcontact ARN (27 lowercase-alnum id chars) that was never created
    filler = "z" * 27
    assert set(filler) <= set(string.ascii_lowercase + string.digits), (
        f"filler {filler!r} must be lowercase-alnum to match the real emailcontact id shape"
    )
    return f"arn:aws:notifications-contacts::{account_id}:emailcontact/{filler}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEmailContact on a syntactically valid but never-created ARN 404s; a real one still deletes fine."""
    client = _nc_client(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = _bogus_contact_arn(account_id)

    code, message = _error(lambda: client.delete_email_contact(arn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Email Contact with arn {bogus_arn} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control in the same file: deleting a real, just-created contact succeeds
    name = ctx.unique_name("sim2real-nc-realdelete-")
    arn = client.create_email_contact(name=name, emailAddress=f"{name}@example.com")["arn"]

    def _cleanup():
        try:
            client.delete_email_contact(arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    client.delete_email_contact(arn=arn)

    code, message = _error(lambda: client.get_email_contact(arn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Email Contact with arn {arn} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
