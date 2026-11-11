"""representation-default-application-setting-empty-vs-absent-preserved."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "representation-default-application-setting-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:opensearch-default-application-setting")
def run(ctx) -> None:
    """PutDefaultApplicationSetting(setAsDefault=True) round-trips the exact applicationArn;
    clearing it with setAsDefault=False makes the setting absent (ResourceNotFoundException)."""
    opensearch = ctx.client("opensearch")

    original_arn = _get_default_arn(opensearch)

    def _restore():
        if original_arn is not None:
            opensearch.put_default_application_setting(
                applicationArn=original_arn, setAsDefault=True
            )

    ctx.on_cleanup(_restore)

    app_name = _app_name(ctx)
    app = opensearch.create_application(
        name=app_name, tagList=[{"Key": "sim2real", "Value": CHECK}]
    )
    app_id = app["id"]
    app_arn = app["arn"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    _wait_application_active(ctx, opensearch, app_id)

    opensearch.put_default_application_setting(applicationArn=app_arn, setAsDefault=True)
    present_arn = opensearch.get_default_application_setting()["applicationArn"]
    assert present_arn == app_arn, f"default arn mangled: {present_arn!r} != {app_arn!r}"

    opensearch.put_default_application_setting(applicationArn=app_arn, setAsDefault=False)
    code, message = _error(lambda: opensearch.get_default_application_setting())
    assert code == "ResourceNotFoundException", (
        f"expected the cleared default setting to be absent (ResourceNotFoundException), "
        f"got {code!r}"
    )
    expected = "No default application is set for this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

def _app_name(ctx) -> str:
    return f"sim2real-{uuid.uuid4().hex[:12]}"


def _error(fn):
    """Call fn() and return its botocore (code, message); an unexpected success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _get_default_arn(opensearch):
    from botocore.exceptions import ClientError

    try:
        return opensearch.get_default_application_setting()["applicationArn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _wait_application_active(ctx, opensearch, app_id, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state")
        time.sleep(3)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
