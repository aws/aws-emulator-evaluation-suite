"""tag-resource-exceeds-max-entries-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-max-entries-rejected"
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
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with 201 tags, over the maximum of 200, fails with ValidationException and the exact
    message and adds none; a single tag Team=sim2real then applies."""
    client = _nc_client(ctx)
    name = ctx.unique_name("sim2real-nc-maxtags-")
    arn = client.create_email_contact(name=name, emailAddress=f"{name}@example.com")["arn"]
    ctx.on_cleanup(lambda: client.delete_email_contact(arn=arn))

    too_many_tags = {f"k{i}": "v" for i in range(201)}  # max is 200
    code, message = _error(lambda: client.tag_resource(arn=arn, tags=too_many_tags))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "[object has too many properties (found 201 but schema requires at most 200)]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: none of the over-quota tags were persisted
    fetched = client.list_tags_for_resource(arn=arn)["tags"]
    assert fetched == {}, f"expected no tags after rejected over-quota call, got {fetched}"

    # positive control in the same file: a normal, within-quota tag call still succeeds
    client.tag_resource(arn=arn, tags={"Team": "sim2real"})
    fetched = client.list_tags_for_resource(arn=arn)["tags"]
    assert fetched == {"Team": "sim2real"}, f"expected {{'Team': 'sim2real'}}, got {fetched}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
