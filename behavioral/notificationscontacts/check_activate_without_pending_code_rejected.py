"""activate-without-pending-code-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-without-pending-code-rejected"
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


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_request_suffix(error.get("Message"))
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateEmailContact on a contact that was never sent an activation code fails with
    ResourceNotFoundException and the exact message and leaves the contact inactive; SendActivationCode
    for the same contact then succeeds."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-noact-")
    arn = client.create_email_contact(name=name, emailAddress=f"{name}@example.com")["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))
    client.tag_resource(arn=arn, tags={"Team": "sim2real"})

    code, message = _error_code(lambda: client.activate_email_contact(arn=arn, code="abc1234"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Activation Token with arn {arn} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: contact is still inactive, not partially/fully activated
    contact = client.get_email_contact(arn=arn)["emailContact"]
    assert contact["status"] == "inactive", f"expected inactive, got {contact['status']!r}"

    # positive control in the same file: the system is otherwise functional -- issuing an
    # activation code for this very contact succeeds normally
    client.send_activation_code(arn=arn)


_REQUEST_SUFFIX = re.compile(
    r" \(Service: [A-Za-z0-9]+, Status Code: \d+, Request ID: [0-9a-fA-F-]+\)"
    r"( \(SDK Attempt Count: \d+\))?$"
)


def _without_request_suffix(message: str) -> str:
    """The message minus its per-request "(Service: ..., Request ID: ...) (SDK Attempt Count: n)"
    suffix, which is the only part that differs between calls."""
    return _REQUEST_SUFFIX.sub("", message or "")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
