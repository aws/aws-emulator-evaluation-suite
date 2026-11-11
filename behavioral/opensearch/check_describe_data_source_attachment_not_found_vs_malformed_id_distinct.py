"""describe-data-source-attachment-not-found-vs-malformed-id-distinct."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-data-source-attachment-not-found-vs-malformed-id-distinct"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDataSourceAttachment answers a well-formed pair with no attachment with
    ResourceNotFoundException and an id breaking the application-id pattern with
    ValidationException, two distinct codes, and neither call affects the application.
    """
    client = ctx.client("opensearch")
    app_id = _create_application(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Own account id: a foreign account would draw an access rejection, not "not found".
    missing_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name('sim2real-ds-')}"

    missing_code, missing_message = _error(
        lambda: client.describe_data_source_attachment(id=app_id, dataSourceArn=missing_arn)
    )
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent attachment, "
        f"got {missing_code!r}"
    )
    expected_missing = (
        f"Data source attachment not found for application {app_id} and data source {missing_arn}"
    )
    assert missing_message == expected_missing, (
        f"expected message {expected_missing!r}, got {missing_message!r}"
    )


    # A well-formed ARN keeps the upper-case `id` the only invalid input.
    well_formed_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{ctx.unique_name('sim2real-ds2-')}"
    malformed_code, malformed_message = _error(
        lambda: client.describe_data_source_attachment(
            id="NOT-A-VALID-APP-ID", dataSourceArn=well_formed_arn
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a malformed application id, got {malformed_code!r}"
    )
    expected_malformed = (
        "1 validation error detected: Value 'NOT-A-VALID-APP-ID' at 'id' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^(?!-)[a-z0-9\\-]{3,30}$"
    )
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )
    assert malformed_code != missing_code, (
        "malformed-input and resource-not-found rejections must not collapse into the same "
        "error code"
    )


    still = client.get_application(id=app_id)
    assert still["status"] == "ACTIVE", f"application unexpectedly affected: {still}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = client.create_application(
        name=name, tagList=[{"Key": "sim2real", "Value": "audit"}]
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
