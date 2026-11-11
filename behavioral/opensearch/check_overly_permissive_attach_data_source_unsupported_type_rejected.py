"""overly-permissive-attach-data-source-unsupported-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "overly-permissive-attach-data-source-unsupported-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDataSource with an EC2 instance ARN fails with ValidationException and its exact message and
    records nothing, while a domain ARN of a domain that does not exist is accepted as PENDING.
    """
    client = ctx.client("opensearch")
    app_id = _create_application(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    control_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name('sim2real-src-')}"
    control_response = {"value": client.attach_data_source(id=app_id, dataSourceArn=control_arn)}
    # Note: a PENDING attachment cannot be detached (DetachDataSource documents a
    # ConflictException for that state) -- DeleteApplication cascading cleanup (registered by
    # _create_application) removes it instead.

    assert control_response["value"]["status"] == "PENDING", (
        f"expected a fresh, not-yet-active-domain attachment to start PENDING, got "
        f"{control_response['value']!r}"
    )

    unsupported_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/i-0123456789abcdef0"
    negative_code, negative_message = _error(
        lambda: client.attach_data_source(id=app_id, dataSourceArn=unsupported_arn)
    )
    assert negative_code == "ValidationException", negative_code
    # The refusal is the dataSourceArn shape check: its service segment admits letters only.
    expected_message = (
        f"1 validation error detected: Value '{unsupported_arn}' at 'dataSourceArn' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "arn:aws[a-z\\-]*:[a-z]+:[a-z0-9\\-]*:[0-9]*:[a-z0-9\\-]+/[a-z0-9_\\-]+"
    )
    assert negative_message == expected_message, (
        f"expected message {expected_message!r}, got {negative_message!r}"
    )

    # Effect absent: no attachment for the rejected EC2 ARN was created, and the earlier,
    # valid attachment is still present and untouched.
    attachments = client.list_data_source_attachments(id=app_id)["attachments"]
    assert all(a["dataSourceArn"] != unsupported_arn for a in attachments), (
        f"an attachment for the rejected EC2 ARN leaked into the list: {attachments!r}"
    )
    assert any(a["dataSourceArn"] == control_arn for a in attachments), (
        f"the valid control attachment disappeared: {attachments!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = client.create_application(
        name=name, tagList=[{"Key": "sim2real", "Value": "overly-permissive-attach-data-source"}]
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        got = client.get_application(id=app_id)
        status = got.get("status")
        if status == "ACTIVE":
            return app_id
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status: {got}")
        time.sleep(3)
    raise AssertionError(f"application {app_id} did not reach ACTIVE (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
