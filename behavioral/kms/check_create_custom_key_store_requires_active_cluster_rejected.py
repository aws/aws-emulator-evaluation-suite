"""create-custom-key-store-requires-active-cluster-rejected."""
from __future__ import annotations

import datetime as _dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-key-store-requires-active-cluster-rejected"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomKeyStore on an existing but uninitialized CloudHSM cluster raises
    CloudHsmClusterNotActiveException and creates no store; a non-existent cluster id raises the
    different CloudHsmClusterNotFoundException, so the state check is specific.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ec2 = ctx.client("ec2")
    cloudhsmv2 = ctx.client("cloudhsmv2")
    kms = ctx.client("kms")

    subnet_ids = _create_network(ctx, ec2)

    cluster = cloudhsmv2.create_cluster(
        HsmType="hsm2m.medium",
        Mode="NON_FIPS",
        SubnetIds=subnet_ids,
        BackupRetentionPolicy={"Type": "DAYS", "Value": "7"},
        TagList=[{"Key": "Name", "Value": ctx.unique_name("sim2real-kms-cluster-")}],
    )["Cluster"]
    cluster_id = cluster["ClusterId"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, cloudhsmv2, cluster_id))

    state = _poll_until(
        lambda: cloudhsmv2.describe_clusters(
            Filters={"clusterIds": [cluster_id]}
        )["Clusters"][0]["State"],
        lambda s: s not in ("CREATE_IN_PROGRESS",),
        timeout_s=220,
        interval_s=10,
    )
    assert state != "ACTIVE", f"cluster unexpectedly reached ACTIVE with no HSM activation: {state}"

    cert_pem = _self_signed_cert_pem(x509, hashes, serialization, rsa, NameOID)

    store_name = ctx.unique_name("sim2real-kms-cks-")
    refused = _error(
        lambda: kms.create_custom_key_store(
            CustomKeyStoreName=store_name,
            CloudHsmClusterId=cluster_id,
            TrustAnchorCertificate=cert_pem,
            KeyStorePassword="Sim2RealPw1",
        )
    )
    expected = ("CloudHsmClusterNotActiveException", "Cluster is not active.")
    assert refused == expected, f"expected {expected!r}, got {refused!r}"

    # Effect absent: no custom key store with this name was created.
    not_found = _error(lambda: kms.describe_custom_key_stores(CustomKeyStoreName=store_name))
    expected_not_found = ("CustomKeyStoreNotFoundException", "")  # KMS sends no message
    assert not_found == expected_not_found, f"expected {expected_not_found!r}, got {not_found!r}"

    # Differentiating control: a syntactically valid but non-existent cluster id gets a
    # *different* error code, proving the check above is state-specific, not a catch-all.
    bogus_cluster_id = "cluster-abcdefghijkl"
    other = _error(
        lambda: kms.create_custom_key_store(
            CustomKeyStoreName=ctx.unique_name("sim2real-kms-cks-"),
            CloudHsmClusterId=bogus_cluster_id,
            TrustAnchorCertificate=cert_pem,
            KeyStorePassword="Sim2RealPw1",
        )
    )
    expected_other = ("CloudHsmClusterNotFoundException", "")  # KMS sends no message
    assert other == expected_other, f"expected {expected_other!r}, got {other!r}"
    assert other[0] != refused[0], (
        f"not-active and not-found rejections must carry different codes, both got {refused[0]}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises: accepting
    input real AWS refuses must not be masked as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_network(ctx, ec2):
    """A VPC this check owns, with one subnet in each of two Availability Zones."""
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-kms-cks-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(ctx, lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    ]
    assert len(zones) >= 2, f"need two Availability Zones for a CloudHSM cluster, found {zones}"
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=zone
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda _s=subnet_id: _retry_dependency(ctx, lambda: ec2.delete_subnet(SubnetId=_s))
        )
        subnet_ids.append(subnet_id)
    return subnet_ids


# One deadline shared by all of the check's teardowns, inside the suite's 900 s cleanup budget.
_TEARDOWN_S = 840.0
_DEADLINES: dict = {}


def _deadline(ctx) -> float:
    """The run's teardown deadline, started by its first teardown."""
    held = _DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_S)
    return held[1]


def _retry_dependency(ctx, fn):
    """Retry a network delete every 2 s while released ENIs still hold it; raise at the shared deadline."""
    deadline = _deadline(ctx)
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _delete_cluster_and_wait(ctx, cloudhsmv2, cluster_id: str):
    """Delete the cluster and poll every 2 s until it reads DELETED, so its ENIs release the subnets.
    A cluster still CREATE_IN_PROGRESS refuses DeleteCluster with CloudHsmInvalidRequestException,
    which is retried; all to the shared deadline."""
    deadline = _deadline(ctx)
    while True:
        clusters = cloudhsmv2.describe_clusters(Filters={"clusterIds": [cluster_id]})["Clusters"]
        state = clusters[0]["State"] if clusters else "DELETED"
        if state == "DELETED":
            return
        if not state.endswith("_IN_PROGRESS"):
            try:
                cloudhsmv2.delete_cluster(ClusterId=cluster_id)
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "CloudHsmResourceNotFoundException":
                    return
                if code != "CloudHsmInvalidRequestException":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_id!r} still {state!r} at the teardown deadline")
        time.sleep(2)


def _self_signed_cert_pem(x509, hashes, serialization, rsa, NameOID):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-kms-trust-anchor")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1))
        .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never met within {timeout_s}s, last value: {value}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
