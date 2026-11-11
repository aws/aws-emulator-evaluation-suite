"""overly-permissive-attach-data-source-cross-account-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-attach-data-source-cross-account-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDataSource with a domain ARN of another account fails with ValidationException and its exact
    message and records no attachment, while the caller's own domain attaches and reaches ATTACHED.
    """
    domain_name = _domain_name(ctx, "att")
    _create_minimal_domain(ctx, domain_name)
    domain_status = _wait_domain_active(ctx, domain_name)
    domain_arn = domain_status["ARN"]

    opensearch = ctx.client("opensearch")
    app_name = _app_name(ctx)
    app_id = opensearch.create_application(name=app_name)["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, app_id))
    _wait_application_active(ctx, app_id)

    cross_account_arn = _cross_account_arn(domain_arn)
    code, message = _client_error(
        lambda: opensearch.attach_data_source(id=app_id, dataSourceArn=cross_account_arn),
        "AttachDataSource of a cross-account domain ARN",
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        f"dataSourceArn account {cross_account_arn.split(':')[4]} does not match caller account "
        f"{domain_arn.split(':')[4]}"
    ), f"unexpected refusal message: {message!r}"

    # Effect absent: no attachment record for the bogus cross-account ARN was created.
    attachments = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert not any(a["dataSourceArn"] == cross_account_arn for a in attachments), (
        f"a rejected cross-account ARN leaked into the attachment list: {attachments!r}"
    )

    # Positive control: attaching the caller's own (same-account) active domain succeeds.
    attach_resp = opensearch.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    ctx.on_cleanup(lambda: _detach(ctx, app_id, domain_arn))
    assert attach_resp["dataSourceArn"] == domain_arn, (
        f"expected the attach response to echo {domain_arn!r}, got {attach_resp!r}"
    )
    attachment = _wait_attachment_status(ctx, app_id, domain_arn, "ATTACHED")
    assert attachment["status"] == "ATTACHED", f"expected ATTACHED, got {attachment!r}"


def _client_error(fn, what: str) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success is a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"{what} must be rejected, but it succeeded: {resp!r}")


def _domain_name(ctx, tag: str) -> str:
    return f"sim2real-{tag}-{uuid.uuid4().hex[:10]}"[:28]


def _app_name(ctx) -> str:
    return f"sim2real-app-{uuid.uuid4().hex[:10]}"[:30]


def _create_minimal_domain(ctx, name, *, instance_count: int = 1, instance_type: str = "t3.small.search") -> None:
    opensearch = ctx.client("opensearch")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": instance_type,
            "InstanceCount": instance_count,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, name))


def _delete_domain(ctx, name) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_application(ctx, app_id) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _detach(ctx, app_id, data_source_arn) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.detach_data_source(id=app_id, dataSourceArn=data_source_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s: float = 1800.0, interval_s: float = 30.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


def _wait_application_active(ctx, app_id, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s")


def _wait_attachment_status(ctx, app_id, data_source_arn, want, timeout_s: float = 600.0, interval_s: float = 10.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    resp = None
    while time.monotonic() < deadline:
        resp = opensearch.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        last = resp["status"]
        if last == want:
            return resp
        if last == "FAILED":
            raise AssertionError(f"attachment for {data_source_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"attachment status never reached {want}, last={last}, resp={resp}")


def _cross_account_arn(domain_arn: str) -> str:
    # domain_arn: arn:aws:es:region:account-id:domain/domain-name Keep the domain-name segment
    # inside the same 28-char pattern every same-account domain in this file uses, so the only
    # variable under test is the account id.
    parts = domain_arn.split(":")
    own_account = parts[4]
    fake_account = "111122223333" if own_account != "111122223333" else "444455556666"
    parts[4] = fake_account
    parts[5] = f"domain/sim2real-xacct-{uuid.uuid4().hex[:8]}"
    return ":".join(parts)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
