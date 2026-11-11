"""get-attachment-before-completion-rejected."""
from __future__ import annotations

import json
import ssl
import time
import urllib.request
import uuid

from behavioral_harness import tags


CHECK = "get-attachment-before-completion-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectparticipant"]
# Cost: nothing here is optional on any backend. A run creates one Connect instance and
# deletes it in its teardown.


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetAttachment on an uploaded attachment not yet finalized by CompleteAttachmentUpload fails with
    ValidationException, and the same attachment returns a presigned Url once it is completed."""
    session = _setup_chat_session(ctx)
    cp = session["cp"]
    token = session["connection_token"]

    payload = b"sim2real not-yet-complete payload"
    start = cp.start_attachment_upload(
        ContentType="text/plain",
        AttachmentSizeInBytes=len(payload),
        AttachmentName="sim2real-pending.txt",
        ClientToken=str(uuid.uuid4()),
        ConnectionToken=token,
    )
    attachment_id = start["AttachmentId"]
    upload_meta = start["UploadMetadata"]
    # The upload URL is presigned, so its signature covers the host: send the route headers.
    upload_url, route_headers = ctx.endpoint_route(upload_meta["Url"])
    req = urllib.request.Request(
        upload_url,
        data=payload,
        method="PUT",
        headers={**dict(upload_meta.get("HeadersToInclude", {})), **route_headers},
    )
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
        if resp.status not in (200, 201, 204):
            raise AssertionError(f"S3 PUT failed with status {resp.status}")

    code = _error_code(lambda: cp.get_attachment(AttachmentId=attachment_id, ConnectionToken=token))
    assert code == "ValidationException", (
        f"expected GetAttachment on a not-yet-completed attachment to be rejected with "
        f"ValidationException, got {code!r}"
    )

    cp.complete_attachment_upload(AttachmentIds=[attachment_id], ClientToken=str(uuid.uuid4()), ConnectionToken=token)
    got = _get_attachment_when_ready(cp, attachment_id, token)
    assert got["Url"], "expected a pre-signed URL once the attachment is completed"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _get_attachment_when_ready(cp, attachment_id: str, token: str, timeout_s=60.0, interval_s=2.0) -> dict:
    """GetAttachment is documented as "an asynchronous API": CompleteAttachmentUpload can return
    before the attachment is retrievable, and a too-early GetAttachment answers
    ValidationException rather than a not-ready-specific code."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.get_attachment(AttachmentId=attachment_id, ConnectionToken=token)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ValidationException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)

def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _error_code(fn):
    """Call fn(); return its error code, raising if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


# Each run creates its own Connect instance (and, for attachments, its own bucket) and deletes
# them in its teardown. Connect limits how many instances an account creates or deletes in 30
# days, so a run creates exactly one.
_CP_ALIAS_PREFIX = "sim2real-cprun-"
_CP_DELETE_TIMEOUT_S = 300.0


def _flow_content() -> str:
    # A "Wait" action between the two reproducibly draws InvalidContactFlowException from
    # CreateContactFlow; this shape keeps the chat open long enough for every check here.
    msg_id = "11111111-1111-1111-1111-111111111111"
    disconnect_id = "33333333-3333-3333-3333-333333333333"
    return json.dumps(
        {
            "Version": "2019-10-30",
            "StartAction": msg_id,
            "Actions": [
                {
                    "Identifier": msg_id,
                    "Type": "MessageParticipant",
                    "Transitions": {"NextAction": disconnect_id, "Errors": [], "Conditions": []},
                    "Parameters": {"Text": "Hello, how can I help you today?"},
                },
                {
                    "Identifier": disconnect_id,
                    "Type": "DisconnectParticipant",
                    "Transitions": {},
                    "Parameters": {},
                },
            ],
        }
    )


def _code(err) -> str:
    return err.response.get("Error", {}).get("Code", "")


def _delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if _code(err) != "NoSuchBucket":
            raise


def _delete_instance(connect, s3, instance_id: str, buckets: list) -> None:
    """DeleteInstance takes the instance's flows, storage associations and chats with it, and the
    deletion is complete once DescribeInstance answers ResourceNotFoundException. The buckets
    outlive the instance, so they go last."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _CP_DELETE_TIMEOUT_S
    while True:
        try:
            connect.delete_instance(InstanceId=instance_id)
            break
        except ClientError as err:
            if _code(err) == "ResourceNotFoundException":
                break
            # An instance still being created refuses deletion until its creation settles.
            if _code(err) != "InvalidRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(15)
    while True:
        try:
            connect.describe_instance(InstanceId=instance_id)
        except ClientError as err:
            if _code(err) == "ResourceNotFoundException":
                break
            raise
        if time.monotonic() > deadline:
            raise AssertionError(
                f"Connect instance {instance_id} still exists {_CP_DELETE_TIMEOUT_S:.0f}s after DeleteInstance"
            )
        time.sleep(10)
    for bucket in buckets:
        _delete_bucket(s3, bucket)


def _create_instance(ctx, connect) -> tuple:
    """A new, ACTIVE Connect instance whose teardown is registered before anything can fail;
    returns its id and the list its teardown deletes buckets from."""
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name(_CP_ALIAS_PREFIX).lower()[:45],
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
    )["Id"]
    buckets: list = []
    s3 = ctx.client("s3")
    ctx.on_cleanup(lambda: _delete_instance(connect, s3, instance_id, buckets))
    status = _poll_until(
        lambda: connect.describe_instance(InstanceId=instance_id)["Instance"]["InstanceStatus"],
        lambda status: status != "CREATION_IN_PROGRESS",
        timeout_s=300,
        interval_s=5,
    )
    assert status == "ACTIVE", f"Connect instance {instance_id} ended {status!r}, not ACTIVE"
    return instance_id, buckets


def _enable_attachments(ctx, connect, instance_id: str, buckets: list) -> None:
    """StartAttachmentUpload answers AccessDeniedException until the instance has an ATTACHMENTS
    storage config and ValidationException until chat attachments are allowed; CreateInstance
    provisions neither. The bucket is this run's own and is deleted after the instance."""
    s3 = ctx.client("s3")
    bucket = f"{_CP_ALIAS_PREFIX}{instance_id}".lower()
    if ctx.region == "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    buckets.append(bucket)
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ConnectAttachmentsAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "connect.amazonaws.com"},
                        "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                        "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
                    }
                ],
            }
        ),
    )
    connect.associate_instance_storage_config(
        InstanceId=instance_id,
        ResourceType="ATTACHMENTS",
        StorageConfig={"StorageType": "S3", "S3Config": {"BucketName": bucket, "BucketPrefix": "attachments"}},
    )
    connect.update_attached_files_configuration(
        InstanceId=instance_id,
        AttachmentScope="CHAT",
        ExtensionConfiguration={"AllowedExtensions": [{"Extension": "txt"}]},
        MaximumSizeLimitInBytes=10_485_760,
    )


def _attachment_upload_ready(session: dict) -> bool:
    try:
        session["cp"].start_attachment_upload(
            ContentType="text/plain",
            AttachmentSizeInBytes=1,
            AttachmentName="sim2real-ready.txt",
            ClientToken=str(uuid.uuid4()),
            ConnectionToken=session["connection_token"],
        )
        return True
    except Exception as exc:
        if type(exc).__name__ not in ("ValidationException", "AccessDeniedException"):
            raise
        return False


def _start_chat_contact(ctx, display_name: str = "sim2real-customer") -> dict:
    connect = ctx.client("connect")
    cp = ctx.client("connectparticipant")
    instance_id, buckets = _create_instance(ctx, connect)
    contact_flow_id = connect.create_contact_flow(
        InstanceId=instance_id,
        Name=ctx.unique_name("sim2real-cprun-flow-"),
        Type="CONTACT_FLOW",
        Status="PUBLISHED",
        Content=_flow_content(),
    )["ContactFlowId"]
    _enable_attachments(ctx, connect, instance_id, buckets)
    chat = connect.start_chat_contact(
        InstanceId=instance_id,
        ContactFlowId=contact_flow_id,
        ParticipantDetails={"DisplayName": display_name},
        ChatDurationInMinutes=60,
    )
    return {
        "connect": connect,
        "cp": cp,
        "instance_id": instance_id,
        "contact_flow_id": contact_flow_id,
        "contact_id": chat["ContactId"],
        "participant_token": chat["ParticipantToken"],
    }


def _connect_participant(session: dict, types=("CONNECTION_CREDENTIALS",)) -> dict:
    resp = session["cp"].create_participant_connection(
        ParticipantToken=session["participant_token"], Type=list(types)
    )
    if "ConnectionCredentials" in resp:
        session["connection_token"] = resp["ConnectionCredentials"]["ConnectionToken"]
    return resp


def _setup_chat_session(ctx, display_name: str = "sim2real-customer") -> dict:
    session = _start_chat_contact(ctx, display_name)
    _connect_participant(session)
    # A new storage association takes a while to reach the data plane, which answers
    # ValidationException or AccessDeniedException until then.
    _poll_until(lambda: _attachment_upload_ready(session), bool, timeout_s=180, interval_s=5)
    return session


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
