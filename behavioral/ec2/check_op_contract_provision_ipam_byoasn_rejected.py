"""op-contract-provision-ipam-byoasn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-provision-ipam-byoasn-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ProvisionIpamByoasn fails with InvalidIpamId.NotFound for an unknown IpamId, and with
    InvalidParameterValue "Asn format is invalid" for a malformed ASN once IpamId names a real IPAM:
    AWS validates the IPAM before the ASN format."""
    ec2 = ctx.client("ec2")

    # error boundary #1: a nonexistent IpamId is rejected on the IpamId itself, even
    # though the Asn in the same request is equally malformed. This is the discriminator
    # that separates "checks ASN format" from "rejects every call": a target that always
    # answers InvalidParameterValue regardless of which field is wrong fails this boundary.
    boundary1, message1, _ = _client_error(
        lambda: ec2.provision_ipam_byoasn(
            IpamId="ipam-00000000000000000",
            Asn="not-an-asn",
            AsnAuthorizationContext={"Message": "test-message", "Signature": "test-signature"},
        )
    )
    assert boundary1 == "InvalidIpamId.NotFound", f"expected InvalidIpamId.NotFound, got {boundary1}"
    assert message1 == "The ipam ID 'ipam-00000000000000000' does not exist", f"unexpected InvalidIpamId.NotFound message: {message1!r}"

    # error boundary #2: once IpamId resolves to a real IPAM, the malformed Asn itself
    # is what gets rejected.
    ipam, created = _get_or_create_ipam(ctx, ec2)
    ipam_id = ipam["IpamId"]
    if created:
        ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    boundary2, message2, _ = _client_error(
        lambda: ec2.provision_ipam_byoasn(
            IpamId=ipam_id,
            Asn="not-an-asn",
            AsnAuthorizationContext={"Message": "test-message", "Signature": "test-signature"},
        )
    )
    assert boundary2 == "InvalidParameterValue", f"expected InvalidParameterValue, got {boundary2}"
    assert message2 == "Asn format is invalid", f"unexpected InvalidParameterValue message: {message2!r}"


def _get_or_create_ipam(ctx, ec2):
    """Return (ipam, created) for an IPAM to run this rejection test against.

    Accounts have a default limit of one IPAM per region; if a prior run (or a
    concurrently running check) already created one, reuse it instead of
    failing the whole check with ResourceLimitExceeded.
    """
    from botocore.exceptions import ClientError

    try:
        name = ctx.unique_name("sim2real-behav-ipam-")
        ipam = ec2.create_ipam(
            Description=name,
            OperatingRegions=[{"RegionName": ctx.region}],
            TagSpecifications=[
                {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]},
            ],
        )["Ipam"]
        return ipam, True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
            raise
        existing = ec2.describe_ipams()["Ipams"]
        if not existing:
            raise
        return existing[0], False


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
