"""complete-attachment-upload-twice-conflict-rejected."""

from __future__ import annotations

import json
import ssl
import time
import urllib.request
import uuid

from behavioral_harness import tags

CHECK = "complete-attachment-upload-twice-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["connectparticipant"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """Completing the same attachment twice never creates a second attachment: whatever the second
    CompleteAttachmentUpload answers, the chat transcript carries that attachment exactly once. A
    second, distinct attachment in the same session completes normally (positive control)."""
    session = _setup_chat_session(ctx)
    cp = session["cp"]
    token = session["connection_token"]

    attachment_id = _upload_and_start_complete(ctx, cp, token, b"first attachment payload")
    cp.complete_attachment_upload(
        AttachmentIds=[attachment_id],
        ClientToken=str(uuid.uuid4()),
        ConnectionToken=token,
    )

    code = _error_code(
        lambda: cp.complete_attachment_upload(
            AttachmentIds=[attachment_id],
            ClientToken=str(uuid.uuid4()),
            ConnectionToken=token,
        )
    )
    # The second call is either accepted idempotently or refused; anything else (a permission or
    # not-found error) means the session itself broke and the effect below would prove nothing.
    assert code in (_CALL_SUCCEEDED, "ValidationException", "ConflictException"), (
        f"the duplicate completion must be accepted or refused, not fail otherwise: got {code!r}"
    )
    assert _transcript_count(cp, token, attachment_id) == 1, (
        f"a duplicate completion (second call answered {code!r}) must not put attachment "
        f"{attachment_id!r} into the transcript twice"
    )

    # positive control: a second, distinct attachment completes normally and is listed once
    other_id = _upload_and_start_complete(ctx, cp, token, b"second attachment payload")
    cp.complete_attachment_upload(
        AttachmentIds=[other_id], ClientToken=str(uuid.uuid4()), ConnectionToken=token
    )
    # GetAttachment refuses (ValidationException) until Connect has scanned the file; the
    # transcript lists it IN_PROGRESS for a few seconds first. Wait for APPROVED.
    assert _attachment_status(cp, token, other_id) == "APPROVED"
    got = cp.get_attachment(AttachmentId=other_id, ConnectionToken=token)
    assert got["Url"]
    assert _transcript_count(cp, token, other_id) == 1


def _attachment_status(
    cp, token: str, attachment_id: str, timeout_s: float = 120.0
) -> str:
    """The attachment's transcript Status once it leaves IN_PROGRESS (bounded wait)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        page = cp.get_transcript(
            ConnectionToken=token, SortOrder="ASCENDING", MaxResults=100
        )
        for item in page.get("Transcript", []):
            for a in item.get("Attachments") or []:
                if a.get("AttachmentId") == attachment_id:
                    status = a.get("Status")
        if status and status != "IN_PROGRESS":
            return status
        time.sleep(3)
    return status or "MISSING"


#: How long to keep watching the transcript after an attachment first appears, so a late duplicate
#: entry is still counted.
_DUPLICATE_HOLD_S = 30.0


def _transcript_count(
    cp, token: str, attachment_id: str, timeout_s: float = 60.0
) -> int:
    """The most transcript items ever seen carrying ``attachment_id``.

    Polls until the attachment first appears (bounded by ``timeout_s``), then keeps polling for a
    further ``_DUPLICATE_HOLD_S``: a duplicate that propagates a few seconds after the first entry is
    exactly what this count exists to catch, so returning on the first sighting would hide it."""
    deadline = time.monotonic() + timeout_s
    hold_until = None
    most = 0
    while True:
        items, next_token = [], None
        while True:
            kwargs = {
                "ConnectionToken": token,
                "SortOrder": "ASCENDING",
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            page = cp.get_transcript(**kwargs)
            items += page.get("Transcript", [])
            next_token = page.get("NextToken")
            if not next_token:
                break
        n = sum(
            1
            for item in items
            if any(
                a.get("AttachmentId") == attachment_id
                for a in item.get("Attachments") or []
            )
        )
        most = max(most, n)
        now = time.monotonic()
        if most and hold_until is None:
            hold_until = now + _DUPLICATE_HOLD_S
        if (hold_until is not None and now >= hold_until) or (
            hold_until is None and now >= deadline
        ):
            return most
        time.sleep(3)


#: When this run associated the instance's ATTACHMENTS storage (time.monotonic()); see
#: _enable_attachments. StartAttachmentUpload is only retried inside the propagation window after it.
_ATTACHMENTS_ENABLED_AT: list[float] = []
#: For a freshly associated ATTACHMENTS storage config, StartAttachmentUpload answers
#: "ValidationException: Specified request parameter(s) are invalid" for every file type and size --
#: even after a successful SendMessage -- and the same calls succeed once 60 s have passed. 180 s
#: bounds that propagation with margin.
_ATTACHMENTS_PROPAGATION_S = 180.0
#: Both answers seen inside that window: ValidationException on a freshly associated instance, and
#: AccessDeniedException right after a reused instance's previous association was swapped out.
_PROPAGATION_CODES = ("ValidationException", "AccessDeniedException")


def _start_attachment_upload(cp, **kwargs):
    from botocore.exceptions import ClientError

    while True:
        try:
            return cp.start_attachment_upload(**kwargs)
        except ClientError as err:
            in_window = bool(_ATTACHMENTS_ENABLED_AT) and (
                time.monotonic() - _ATTACHMENTS_ENABLED_AT[-1]
                < _ATTACHMENTS_PROPAGATION_S
            )
            if err.response["Error"]["Code"] not in _PROPAGATION_CODES or not in_window:
                raise
            time.sleep(2)


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


def _upload_and_start_complete(ctx, cp, token: str, payload: bytes) -> str:
    start = _start_attachment_upload(
        cp,
        ContentType="text/plain",
        AttachmentSizeInBytes=len(payload),
        AttachmentName="sim2real-conflict.txt",
        ClientToken=str(uuid.uuid4()),
        ConnectionToken=token,
    )
    upload_meta = start["UploadMetadata"]
    req = urllib.request.Request(
        ctx.endpoint_url(upload_meta["Url"]),
        data=payload,
        method="PUT",
        headers=dict(upload_meta.get("HeadersToInclude", {})),
    )
    with urllib.request.urlopen(
        req, timeout=30, context=_https_context(ctx.http_verify)
    ) as resp:
        if resp.status not in (200, 201, 204):
            raise AssertionError(f"S3 PUT failed with status {resp.status}")
    return start["AttachmentId"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


_CALL_SUCCEEDED = "<call succeeded>"


def _error_code(fn):
    """fn()'s error code, or _CALL_SUCCEEDED (no code equals it) when the call is accepted."""
    from botocore.exceptions import ClientError

    try:
        fn()
        return _CALL_SUCCEEDED
    except ClientError as err:
        return err.response["Error"]["Code"]


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
            time.sleep(2)
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
        time.sleep(2)
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
        interval_s=2,
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
    _ATTACHMENTS_ENABLED_AT.append(time.monotonic())
    _poll_until(lambda: _attachment_upload_ready(session), bool, timeout_s=180, interval_s=2)
    return session


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
