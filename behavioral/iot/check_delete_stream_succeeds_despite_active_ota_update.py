"""delete-stream-succeeds-despite-active-ota-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "delete-stream-succeeds-despite-active-ota-update"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteStream succeeds while an in-progress OTA update references the stream;
    afterwards DescribeStream and a repeat delete fail with ResourceNotFoundException
    and the exact message."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    iot = ctx.client("iot")

    bucket = ctx.unique_name("sim2real-otastream-").replace("_", "-")[:63]
    key = "firmware/payload.bin"
    # us-east-1 rejects CreateBucket with an explicit LocationConstraint; this
    # branch follows ctx.region, it does not pin one.
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=b"fake-firmware-bytes")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    role_arn = _create_iot_service_role(
        ctx, iam, ctx.unique_name("sim2real-ota-role-"), bucket
    )

    stream_id = ctx.unique_name("sim2real-stream-")
    _create_stream_with_retry(iot, stream_id, bucket, key, role_arn)
    stream_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if stream_deleted["done"] else iot.delete_stream(streamId=stream_id))

    thing_name = ctx.unique_name("sim2real-otathing-")
    thing = iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    ota_id = ctx.unique_name("sim2real-ota-")
    _create_ota_update_with_retry(
        iot, ota_id, thing["thingArn"], stream_id, role_arn
    )
    ota_deleted = {"done": False}

    def _cleanup_ota():
        if not ota_deleted["done"]:
            iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=False, forceDeleteAWSJob=True)

    ctx.on_cleanup(_cleanup_ota)

    # the OTA update job is still active (its lone target never checks in), but
    # AWS IoT does not block DeleteStream on that basis alone
    iot.delete_stream(streamId=stream_id)
    stream_deleted["done"] = True

    # effect present: the stream is actually gone, not a silent no-op
    code_after, message_after = _error_code(lambda: iot.describe_stream(streamId=stream_id))
    assert code_after == "ResourceNotFoundException", (
        f"expected the stream to be gone after delete, got {code_after}"
    )
    assert message_after == f"Requested stream {stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message_after!r}"
    )

    # a mutation on the dead id also fails -- a second delete is rejected,
    # not a silent no-op
    redelete_code, redelete_message = _error_code(lambda: iot.delete_stream(streamId=stream_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting the already-gone stream to fail, got {redelete_code}"
    )
    assert redelete_message == f"Requested stream {stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {redelete_message!r}"
    )

    # the OTA update is unaffected by the stream's deletion -- its file
    # metadata is left holding the now-dangling streamId
    dangling_ota = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
    dangling_stream_id = dangling_ota["otaUpdateFiles"][0]["fileLocation"]["stream"]["streamId"]
    assert dangling_stream_id == stream_id, (
        f"expected the OTA update's file location to still reference {stream_id!r}, "
        f"got {dangling_stream_id!r}"
    )

    # tear down the still-active OTA update job
    iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=False, forceDeleteAWSJob=True)
    ota_deleted["done"] = True
    _wait_ota_deleted(iot, ota_id)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _create_iot_service_role(ctx, iam, role_name: str, bucket: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "iot:CreateJob",
                    "iot:DescribeJob",
                    "iot:DeleteJob",
                    "iot:CancelJob",
                    "iot:UpdateJob",
                    "iot:DescribeStream",
                ],
                "Resource": "*",
            },
        ],
    }
    policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return role_arn


def _create_stream_with_retry(iot, stream_id: str, bucket: str, key: str, role_arn: str):
    """Retries on InvalidRequestException: CreateStream can reject roleArn
    before the just-created IAM role has propagated, so this loop is also
    what absorbs that propagation delay -- there is no separate fixed sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    while True:
        try:
            return iot.create_stream(
                streamId=stream_id,
                files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": key}}],
                roleArn=role_arn,
                tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_ota_update_with_retry(iot, ota_id: str, thing_arn: str, stream_id: str, role_arn: str):
    from botocore.exceptions import ClientError

    cert_pem = _generate_self_signed_cert_pem()
    files = [
        {
            "fileName": "fw.bin",
            "fileVersion": "1",
            "fileLocation": {"stream": {"streamId": stream_id, "fileId": 0}},
            "codeSigning": {
                "customCodeSigning": {
                    "certificateChain": {
                        "certificateName": "sim2real-ota-cert",
                        "inlineDocument": cert_pem,
                    },
                    "signature": {"inlineDocument": b"sim2real-dummy-signature"},
                    "hashAlgorithm": "SHA256",
                    "signatureAlgorithm": "RSA",
                }
            },
        }
    ]
    deadline = time.monotonic() + 60
    while True:
        try:
            return iot.create_ota_update(
                otaUpdateId=ota_id,
                targets=[thing_arn],
                targetSelection="SNAPSHOT",
                files=files,
                roleArn=role_arn,
                tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _generate_self_signed_cert_pem() -> str:
    """Generate a throwaway self-signed certificate PEM for customCodeSigning.

    CreateOTAUpdate validates that certificateChain.inlineDocument parses as a
    real X.509 certificate, so a placeholder string is not sufficient.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-ota-codesign")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _wait_ota_deleted(iot, ota_id: str, timeout_s: float = 60.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iot.get_ota_update(otaUpdateId=ota_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError("OTA update was never fully deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
