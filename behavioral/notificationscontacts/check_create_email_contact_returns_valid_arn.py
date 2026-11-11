"""create-email-contact-returns-valid-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

import re

from behavioral_harness import tags

CHECK = "create-email-contact-returns-valid-arn"
GROUP = "control-plane"
SERVICES = ["notificationscontacts"]

_ARN_RE = re.compile(
    r"^arn:[a-z-]+:notifications-contacts::\d{12}:emailcontact/[a-z0-9]{27}$"
)


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
    """CreateEmailContact returns an ARN of the emailcontact shape, and GetEmailContact on it returns that
    same ARN."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-")
    email = f"{name}@example.com"
    arn = client.create_email_contact(name=name, emailAddress=email)["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))

    assert _ARN_RE.match(arn), f"ARN {arn!r} does not match expected emailcontact ARN shape"

    fetched_arn = client.get_email_contact(arn=arn)["emailContact"]["arn"]
    assert fetched_arn == arn, (
        f"GetEmailContact returned arn {fetched_arn!r}, expected {arn!r} from create"
    )
    assert _ARN_RE.match(fetched_arn), (
        f"ARN {fetched_arn!r} from independent GetEmailContact read does not match "
        "expected emailcontact ARN shape"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

