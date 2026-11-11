"""detach-data-source-not-attached-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "detach-data-source-not-attached-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachDataSource for a never-attached ARN fails with ResourceNotFoundException, for a PENDING attachment
    with ConflictException (exact messages), and leaves the real attachment in place; once ATTACHED it
    detaches, and a repeat detach fails with ResourceNotFoundException.
    """
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)

    attached_arn = _create_real_domain(ctx, aos, "sim2real-detach-attached")
    never_attached_arn = _bogus_domain_arn(ctx, "sim2real-detach-never")

    aos.attach_data_source(id=app_id, dataSourceArn=attached_arn)
    before = _list_attachment_arns(aos, app_id)
    assert attached_arn in before, "setup attach did not create an attachment record"

    code, message = _error(lambda: aos.detach_data_source(id=app_id, dataSourceArn=never_attached_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Data source {never_attached_arn} is not attached to application {app_id}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_reject = _list_attachment_arns(aos, app_id)
    assert attached_arn in after_reject, "the real attachment was disturbed by the rejected detach"
    assert never_attached_arn not in after_reject, "a bogus attachment was created by the rejected detach"

    # Interim control: the genuine (still in-progress) attachment for a DIFFERENT
    # dataSourceArn on the same application was not disturbed by the rejected call
    # above and remains fully describable.
    control = aos.describe_data_source_attachment(id=app_id, dataSourceArn=attached_arn)
    assert control["dataSourceArn"] == attached_arn
    assert control["status"] in {"PENDING", "ATTACHED"}, f"unexpected attachment status: {control['status']}"

    # Confirmed against real AWS: detaching an attachment that DOES exist but is still
    # PENDING is refused too -- with a different, specific error (ConflictException),
    # not ResourceNotFoundException. This is what distinguishes "not attached at all"
    # from "attached but not yet settled".
    if control["status"] == "PENDING":
        pending_code, pending_message = _error(
            lambda: aos.detach_data_source(id=app_id, dataSourceArn=attached_arn)
        )
        assert pending_code == "ConflictException", (
            f"expected ConflictException for a still-PENDING attachment, got {pending_code}"
        )
        expected_pending = f"Data source {attached_arn} attachment to application {app_id} is still PENDING."
        assert pending_message == expected_pending, (
            f"expected message {expected_pending!r}, got {pending_message!r}"
        )

    # Positive control: once the domain finishes provisioning and the attachment settles
    # into ATTACHED, DetachDataSource on the ARN that IS attached succeeds and actually
    # removes it. Without this, "rejects a never-attached ARN" would be indistinguishable
    # from "DetachDataSource always fails".
    _wait_attachment_status(aos, app_id, attached_arn, "ATTACHED", timeout_s=1800.0)
    aos.detach_data_source(id=app_id, dataSourceArn=attached_arn)
    after_real_detach = _list_attachment_arns(aos, app_id)
    assert attached_arn not in after_real_detach, "positive-control DetachDataSource did not remove the attachment"
    final_code, final_message = _error(
        lambda: aos.describe_data_source_attachment(id=app_id, dataSourceArn=attached_arn)
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after real detach, got {final_code}"
    )
    expected_final = f"Data source attachment not found for application {app_id} and data source {attached_arn}"
    assert final_message == expected_final, f"expected message {expected_final!r}, got {final_message!r}"




def _error(fn) -> "tuple[str, str]":
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as an ordinary code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_application(id=app_id)))
    _wait_application_active(aos, app_id)
    return app_id


def _wait_application_active(aos, app_id: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = aos.get_application(id=app_id).get("status")
        if last != "CREATING":
            return
        time.sleep(3)
    raise AssertionError(f"application {app_id} never left CREATING within {timeout_s}s (last: {last})")



def _wait_attachment_status(aos, app_id: str, arn: str, target: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = aos.describe_data_source_attachment(id=app_id, dataSourceArn=arn).get("status")
        if last == target:
            return
        if last == "FAILED":
            raise AssertionError(f"attachment for {arn} moved to FAILED while waiting for {target}")
        time.sleep(3)
    raise AssertionError(f"attachment for {arn} never reached {target} within {timeout_s}s (last: {last})")


def _bogus_domain_arn(ctx, prefix: str) -> str:

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return f"arn:aws:es:{ctx.region}:{account_id}:domain/{cleaned[:28]}"


def _create_real_domain(ctx, aos, prefix: str) -> str:
    domain_name = _bogus_domain_arn(ctx, prefix).rsplit("/", 1)[-1]
    resp = aos.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_domain(DomainName=domain_name)))
    return resp["DomainStatus"]["ARN"]



def _list_attachment_arns(aos, app_id: str) -> set:
    arns: set = set()
    next_token = None
    while True:
        kwargs = {"id": app_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = aos.list_data_source_attachments(**kwargs)
        for attachment in resp.get("attachments", []):
            arns.add(attachment["dataSourceArn"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
