"""delete-email-contact-removes-resource."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-email-contact-removes-resource"
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




def _error(fn):
    """Call fn(); return its botocore error (code, message without the per-request suffix). An
    unexpected success raises."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteEmailContact, the contact is gone: GetEmailContact 404s, an unrelated one still resolves."""
    client = _nc_client(ctx)

    name = ctx.unique_name("sim2real-nc-")
    arn = client.create_email_contact(name=name, emailAddress=f"{name}@example.com")["arn"]

    # positive control: an unrelated, still-live contact created in the same file
    control_name = ctx.unique_name("sim2real-nc-ctrl-")
    control_arn = client.create_email_contact(
        name=control_name, emailAddress=f"{control_name}@example.com"
    )["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=control_arn))

    client.delete_email_contact(arn=arn)

    code, message = _error(lambda: client.get_email_contact(arn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Email Contact with arn {arn} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control still resolves fine after the sibling delete
    control_contact = client.get_email_contact(arn=control_arn)["emailContact"]
    assert control_contact["arn"] == control_arn, (
        f"expected sibling contact {control_arn!r} to still resolve after the other's delete, "
        f"got {control_contact['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
