"""activate-wrong-code-state-conflict-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-wrong-code-state-conflict-rejected"
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
    """ActivateEmailContact with a well-formed wrong code after SendActivationCode fails with
    ValidationException "Input token did not match stored Activation Token" and leaves the contact
    inactive; the same code on a contact with no code issued fails with ResourceNotFoundException."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-wrongcode-")
    arn = client.create_email_contact(
        name=name, emailAddress=f"{name}@example.com", tags={"sim2real": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))

    client.send_activation_code(arn=arn)

    # a code that is well-formed (7 lowercase alnum chars) but essentially certain not to be
    # the one actually mailed out
    wrong_code = "0000000"
    code, message = _error(lambda: client.activate_email_contact(arn=arn, code=wrong_code))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert "did not match" in message.lower(), (
        f"expected a token-mismatch message, got {message!r}"
    )
    expected = f"Input token did not match stored Activation Token for arn {arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the contact was not activated by the wrong code
    contact = client.get_email_contact(arn=arn)["emailContact"]
    assert contact["status"] == "inactive", f"expected inactive, got {contact['status']!r}"

    # positive control: the SAME wrong_code, presented to a contact for which no activation
    # code was ever issued, must fail with a *different* error (ResourceNotFoundException).
    # This rules out a target that returns ValidationException unconditionally for any
    # arn/code combination -- the real service actually discriminates "wrong code for a
    # genuinely pending one" from "no code was ever issued for this contact".
    control_name = ctx.unique_name("sim2real-nc-wrongcode-ctrl-")
    control_arn = client.create_email_contact(
        name=control_name,
        emailAddress=f"{control_name}@example.com",
        tags={"sim2real": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=control_arn))
    control_code, control_message = _error(
        lambda: client.activate_email_contact(arn=control_arn, code=wrong_code)
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {control_code!r}"
    )
    expected = f"Activation Token with arn {control_arn} not found"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"
    control_contact = client.get_email_contact(arn=control_arn)["emailContact"]
    assert control_contact["status"] == "inactive", (
        f"expected inactive, got {control_contact['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
