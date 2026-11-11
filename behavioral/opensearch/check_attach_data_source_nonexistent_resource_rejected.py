"""attach-data-source-nonexistent-resource-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "attach-data-source-nonexistent-resource-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDataSource to an unknown application fails with ResourceNotFoundException and its exact
    message; attaching an ARN of a domain that does not exist is accepted but never reports ATTACHED,
    and describe and a repeat attach keep the same attachmentId.
    """
    osc = ctx.client("opensearch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # -- boundary 1: application id does not exist --
    bogus_app_id = "sim2real00missingapp"
    real_looking_arn = (
        f"arn:aws:es:{ctx.region}:{account_id}:domain/"
        f"{ctx.unique_name('sim2real-nope-')[:28].rstrip('-')}"
    )
    code1, message1 = _client_error(
        lambda: osc.attach_data_source(id=bogus_app_id, dataSourceArn=real_looking_arn)
    )
    assert code1 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code1!r}"
    expected = f"Application {bogus_app_id} not found for account {account_id}"
    assert message1 == expected, f"missing-application message: expected {expected!r}, got {message1!r}"

    # -- boundary 2: application exists, but dataSourceArn does not --
    app_name = ctx.unique_name("sim2real-app-")[:30].rstrip("-")
    app_id = osc.create_application(name=app_name)["id"]
    ctx.on_cleanup(lambda: _safe(lambda: osc.delete_application(id=app_id)))

    attach_result = osc.attach_data_source(id=app_id, dataSourceArn=real_looking_arn)
    assert attach_result["status"] in ("PENDING", "FAILED"), attach_result["status"]
    assert attach_result["status"] != "ATTACHED", (
        f"expected not ATTACHED for a dataSourceArn with no backing domain, got {attach_result['status']!r}"
    )

    # The domain referenced by dataSourceArn does not exist, so the ARN is validated
    # asynchronously rather than synchronously -- bounded-poll for 15s confirming it stays out of
    # ATTACHED on every read (not faked partway through), and that a repeat call is idempotent
    # (same attachmentId, still not ATTACHED). We do NOT assert an eventual terminal FAILED
    # status: empirically that resolution did not occur within a 5-minute bounded poll against
    # real AWS, so its SLA is unknown/longer than is reasonable to block a test suite on.
    deadline = time.monotonic() + 15.0
    described = attach_result
    while time.monotonic() < deadline:
        time.sleep(3)
        described = osc.describe_data_source_attachment(id=app_id, dataSourceArn=real_looking_arn)
        assert described["status"] != "ATTACHED", (
            f"expected not ATTACHED while polling a dataSourceArn with no backing domain, got {described['status']!r}"
        )
        assert described["attachmentId"] == attach_result["attachmentId"], (
            f"attachmentId changed across reads: {attach_result['attachmentId']!r} -> {described['attachmentId']!r}"
        )

    retry = osc.attach_data_source(id=app_id, dataSourceArn=real_looking_arn)
    assert retry["attachmentId"] == attach_result["attachmentId"], (
        f"repeat AttachDataSource returned a different attachmentId "
        f"({retry['attachmentId']!r} != {attach_result['attachmentId']!r}), implying a duplicate record"
    )
    assert retry["status"] != "ATTACHED", (
        f"expected not ATTACHED on repeat AttachDataSource, got {retry['status']!r}"
    )

    # Terminal read is independent of the mutating attach_data_source call above: confirm via
    # describe_data_source_attachment (a different operation) rather than trusting the attach
    # call's own self-reported response as the last word.
    final_read = osc.describe_data_source_attachment(id=app_id, dataSourceArn=real_looking_arn)
    assert final_read["attachmentId"] == attach_result["attachmentId"], (
        f"independent read after repeat AttachDataSource shows a different attachmentId "
        f"({final_read['attachmentId']!r} != {attach_result['attachmentId']!r})"
    )
    assert final_read["status"] != "ATTACHED", (
        f"independent read after repeat AttachDataSource shows ATTACHED, got {final_read['status']!r}"
    )



def _client_error(fn):
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

