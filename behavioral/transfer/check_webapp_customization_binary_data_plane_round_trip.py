"""webapp-customization-binary-data-plane-round-trip."""
from __future__ import annotations

import json
import struct
import time
import zlib
from botocore.exceptions import ClientError

CHECK = "webapp-customization-binary-data-plane-round-trip"
GROUP = "data-plane"
SERVICES = ["transfer"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateWebAppCustomization accepts a binary logo/favicon payload and
    DescribeWebAppCustomization returns the identical bytes, without transcoding loss."""
    instance_arn = _identity_center_instance_arn(ctx)
    role_arn = _create_transfer_role(ctx)

    transfer = ctx.client("transfer")
    web_app_id = transfer.create_web_app(
        IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["WebAppId"]
    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))

    # UpdateWebAppCustomization validates LogoFile/FaviconFile as real image files (an
    # arbitrary byte string is rejected with InvalidRequestException: Invalid image file
    # format), so the round-trip payload must be a valid image. Each is a 16x16 grayscale
    # PNG whose pixel grid walks the full 0-255 byte range in a distinct order, so any
    # base64/text transcoding bug (e.g. mangled 0x00, 0x0A, or high-bit bytes) would still
    # corrupt the decoded pixels and be caught by the byte-for-byte comparison below.
    logo_bytes = _grayscale_png(lambda i: i)
    favicon_bytes = _grayscale_png(lambda i: 255 - i)

    transfer.update_web_app_customization(
        WebAppId=web_app_id,
        Title="sim2real behavioral check",
        LogoFile=logo_bytes,
        FaviconFile=favicon_bytes,
    )

    described = transfer.describe_web_app_customization(WebAppId=web_app_id)["WebAppCustomization"]
    logo = described["LogoFile"]
    logo = logo.read() if hasattr(logo, "read") else bytes(logo)
    favicon = described["FaviconFile"]
    favicon = favicon.read() if hasattr(favicon, "read") else bytes(favicon)
    assert logo == logo_bytes, (
        f"logo bytes were altered by the round trip: sent {len(logo_bytes)} bytes, got {len(logo)} bytes"
    )
    assert favicon == favicon_bytes, (
        f"favicon bytes were altered by the round trip: sent {len(favicon_bytes)} bytes, "
        f"got {len(favicon)} bytes"
    )
    assert described["Title"] == "sim2real behavioral check", (
        f"expected Title 'sim2real behavioral check', got {described['Title']!r}"
    )


def _grayscale_png(pixel_value) -> bytes:
    """A minimal valid 16x16 8-bit grayscale PNG whose pixel grid is
    ``pixel_value(0..255)``, so the decoded content walks the full byte range."""
    width = height = 16

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = b"".join(
        bytes([0]) + bytes(pixel_value(r * width + c) for c in range(width)) for r in range(height)
    )
    idat = zlib.compress(raw, 9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def _identity_center_instance_arn(ctx) -> str:
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one IAM Identity Center instance is allowed per account, and deleting it
        # would disrupt any other check relying on it, so if we must create one here we
        # deliberately never tear it down.
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise AssertionError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise AssertionError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-transfer-webapp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            iam.get_role(RoleName=name)
            break
        except iam.exceptions.NoSuchEntityException:
            time.sleep(2)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
