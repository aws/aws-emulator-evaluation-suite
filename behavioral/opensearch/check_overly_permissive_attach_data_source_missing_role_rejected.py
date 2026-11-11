"""overly-permissive-attach-data-source-missing-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-attach-data-source-missing-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachDataSource by a caller with no OpenSearch permissions is AccessDeniedException with no
    attachment created; the same call with permitted credentials is accepted and, naming a
    nonexistent domain, never reaches ATTACHED (both checked via independent reads)."""
    opensearch = ctx.client("opensearch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    app_id = _create_active_application(ctx, opensearch)

    role_name = ctx.unique_name("sim2real-noperm-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sess-")[:64]
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    # Re-sign with the permissionless role's credentials while keeping this target's endpoint,
    # region and TLS settings, so the denial comes from the target under test.
    restricted_client = ctx.client(
        "opensearch",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    placeholder_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/sim2real-nonexistent"

    denied_code, denied_message = _client_error(
        lambda: restricted_client.attach_data_source(id=app_id, dataSourceArn=placeholder_arn),
        "AttachDataSource by a caller with no OpenSearch permissions",
    )
    assert denied_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no OpenSearch permissions, "
        f"got {denied_code}"
    )
    assert denied_message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: es:AttachDataSource on resource: arn:aws:es:{ctx.region}:{account_id}:domain/* "
        "because no identity-based policy allows the es:AttachDataSource action"
    ), f"unexpected denial message: {denied_message!r}"

    # Effect absent: an independent read (ListDataSourceAttachments), not the denied call's own
    # response, is what proves the rejection actually stopped the mutation.
    attachments = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    assert not any(a["dataSourceArn"] == placeholder_arn for a in attachments), (
        f"unauthorized AttachDataSource left an attachment despite AccessDeniedException: "
        f"{attachments!r}"
    )

    full_client = ctx.client("opensearch")
    try:
        control_resp = full_client.attach_data_source(id=app_id, dataSourceArn=placeholder_arn)
    except ClientError as e:
        control_code = e.response["Error"]["Code"]
        control_resp = None
    else:
        control_code = None
    assert control_code != "AccessDeniedException", (
        f"full-permission caller must pass the authorization layer, got AccessDeniedException"
    )
    assert control_resp is not None and control_resp.get("status") in ("PENDING", "FAILED"), (
        f"expected the full-permission call against a nonexistent domain to be accepted "
        f"asynchronously (PENDING or already FAILED), got error {control_code!r} / "
        f"response {control_resp!r}"
    )
    # _delete_application's cleanup detaches every attachment on this app before deleting it.

    # Independent read: the accepted attachment must never resolve to ATTACHED, because the
    # domain it names does not exist.
    observed_status = _poll_attachment_status(opensearch, app_id, placeholder_arn)
    assert observed_status != "ATTACHED", (
        f"attachment to a nonexistent domain must never reach ATTACHED, got {observed_status!r}"
    )
    attachments_after = opensearch.list_data_source_attachments(id=app_id)["attachments"]
    matching = [a for a in attachments_after if a["dataSourceArn"] == placeholder_arn]
    assert len(matching) == 1 and matching[0]["status"] != "ATTACHED", (
        f"expected exactly one non-ATTACHED attachment record for the accepted control call, "
        f"got {matching!r}"
    )



def _create_active_application(ctx, opensearch, timeout_s=120.0, interval_s=3.0):
    name = ctx.unique_name("sim2real-osnoperm-").replace("_", "-").lower()[:30].rstrip("-")
    app_id = opensearch.create_application(name=name)["id"]
    ctx.on_cleanup(lambda: _delete_application(opensearch, app_id))
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return app_id
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s, last status {status!r}")


def _poll_attachment_status(opensearch, app_id, data_source_arn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = "PENDING"
    while time.monotonic() < deadline:
        status = opensearch.describe_data_source_attachment(
            id=app_id, dataSourceArn=data_source_arn
        )["status"]
        if status != "PENDING":
            return status
        time.sleep(interval_s)
    return status


def _delete_application(opensearch, app_id):
    try:
        for attachment in opensearch.list_data_source_attachments(id=app_id).get("attachments", []):
            try:
                opensearch.detach_data_source(id=app_id, dataSourceArn=attachment["dataSourceArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        opensearch.delete_application(id=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn, what: str) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success is a failure."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"{what} must be rejected, but it succeeded: {resp!r}")


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
