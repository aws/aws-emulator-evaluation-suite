"""overly-permissive-data-source-attach-unauthorized-role-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "overly-permissive-data-source-attach-unauthorized-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDataSource by a user with no permissions is denied with AccessDeniedException, while
    the permitted caller passes authorization, proving a real permission check; an attachment
    to a nonexistent domain never reaches ATTACHED."""
    opensearch = ctx.client("opensearch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    app_name = _app_name(ctx)
    app = opensearch.create_application(
        name=app_name,
        tagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    app_id = app["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    _wait_application_active(ctx, opensearch, app_id)

    account_id = sts.get_caller_identity()["Account"]
    # Domain names are capped at 28 chars; keep this well under that so the ARN
    # is syntactically valid and the rejection below is a lookup failure, not a
    # pattern-validation failure.
    fake_data_source_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/sim2real-nofind"

    user_name = f"sim2real-behav-noperm-{uuid.uuid4().hex[:10]}"
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    restricted_opensearch = _client_with_creds(
        ctx, "opensearch", access_key_id, key["SecretAccessKey"]
    )
    restricted_sts = _client_with_creds(ctx, "sts", access_key_id, key["SecretAccessKey"])
    _wait_for_credential_propagation(restricted_sts)

    denied_code, denied_message = _client_error(
        lambda: restricted_opensearch.attach_data_source(
            id=app_id, dataSourceArn=fake_data_source_arn
        ),
        "AttachDataSource by a user with no permissions",
    )
    assert denied_code == "AccessDeniedException", f"expected AccessDeniedException, got {denied_code!r}"
    assert denied_message == (
        f"User: arn:aws:iam::{account_id}:user/{user_name} is not authorized to perform: "
        f"es:AttachDataSource on resource: arn:aws:es:{ctx.region}:{account_id}:domain/* "
        "because no identity-based policy allows the es:AttachDataSource action"
    ), f"unexpected denial message: {denied_message!r}"

    # Positive control: the permitted caller is accepted as PENDING; reconciliation is async,
    # so poll a bounded window and require it never reports ATTACHED.
    attach_resp = opensearch.attach_data_source(id=app_id, dataSourceArn=fake_data_source_arn)
    assert attach_resp["status"] in ("PENDING", "FAILED"), (
        f"unexpected initial attachment status: {attach_resp['status']!r}"
    )

    observed_status = _poll_attachment_status(ctx, opensearch, app_id, fake_data_source_arn)
    assert observed_status != "ATTACHED", (
        f"attachment to a nonexistent domain must never reach ATTACHED, got {observed_status!r}"
    )

    # The unauthorized attempt created no extra attachment record.
    attachments = opensearch.list_data_source_attachments(id=app_id).get("attachments", [])
    matching = [a for a in attachments if a.get("dataSourceArn") == fake_data_source_arn]
    assert len(matching) == 1, f"expected exactly one attachment record, found {matching!r}"
    assert matching[0]["status"] != "ATTACHED", (
        f"attachment record for a nonexistent domain must never report ATTACHED, "
        f"got {matching[0]['status']!r}"
    )
def _app_name(ctx) -> str:
    return f"sim2real-{uuid.uuid4().hex[:12]}"


def _client_error(fn, what: str) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success is a failure."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"{what} must be rejected, but it succeeded: {resp!r}")


def _client_with_creds(ctx, service, access_key_id, secret_access_key):
    """Sign as the permissionless user while keeping the context's endpoint and region."""
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _wait_for_credential_propagation(restricted_sts, timeout_s: float = 30.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            restricted_sts.get_caller_identity()
            return
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "InvalidClientTokenId":
                return
            time.sleep(2)
    raise AssertionError(f"new IAM access key never propagated: {last_exc}")


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


def _poll_attachment_status(ctx, opensearch, app_id, data_source_arn, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "PENDING"
    while time.monotonic() < deadline:
        status = opensearch.describe_data_source_attachment(
            id=app_id, dataSourceArn=data_source_arn
        )["status"]
        if status != "PENDING":
            return status
        time.sleep(5)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
