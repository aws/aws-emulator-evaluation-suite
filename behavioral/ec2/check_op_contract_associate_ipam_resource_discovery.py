"""op-contract-associate-ipam-resource-discovery."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-associate-ipam-resource-discovery"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """AssociateIpamResourceDiscovery attaches a resource discovery to an IPAM; a nonexistent
    resource discovery id is rejected."""
    ec2 = ctx.client("ec2")
    # The resource discovery is created BEFORE the IPAM: CreateIpam also creates the IPAM's
    # own default resource discovery, and once that exists a further
    # CreateIpamResourceDiscovery in the same account is refused with ResourceLimitExceeded.
    rd_id = _create_rd(ctx, ec2)
    ipam_id = _create_ipam(ctx, ec2)

    # A just-created IPAM reports a transitional State for a short while, and mutating its
    # resource discovery associations then fails IncorrectState, so wait for create-complete.
    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]["State"],
        lambda s: s == "create-complete",
        timeout_s=120,
        interval_s=5,
    )
    rd_state = _poll_until(
        lambda: ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[rd_id])[
            "IpamResourceDiscoveries"
        ][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=120,
        interval_s=5,
    )
    assert rd_state == "create-complete", f"resource discovery ended in state {rd_state}"

    assoc = ec2.associate_ipam_resource_discovery(IpamId=ipam_id, IpamResourceDiscoveryId=rd_id)[
        "IpamResourceDiscoveryAssociation"
    ]
    assoc_id = assoc["IpamResourceDiscoveryAssociationId"]
    ctx.on_cleanup(lambda: _disassociate_and_wait(ec2, assoc_id))
    assert assoc["IpamId"] == ipam_id, f"expected association on {ipam_id}, got {assoc['IpamId']}"
    assert assoc["IpamResourceDiscoveryId"] == rd_id, (
        f"expected association to reference {rd_id}, got {assoc['IpamResourceDiscoveryId']}"
    )

    state = _poll_until(
        lambda: _association_state(ec2, assoc_id),
        lambda s: s in ("associate-complete", "associate-failed"),
        timeout_s=120,
        interval_s=5,
    )
    assert state == "associate-complete", f"association ended in state {state}"

    fake_rd_id = "ipam-res-disco-00000000000000000"
    code, message = _client_error(
        lambda: ec2.associate_ipam_resource_discovery(IpamId=ipam_id, IpamResourceDiscoveryId=fake_rd_id)
    )
    assert code == "InvalidIpamResourceDiscoveryId.NotFound", f"unexpected error code: {code}: {message!r}"
    expected = f"The ipam-resource-discovery ID '{fake_rd_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _association_state(ec2, assoc_id):
    associations = ec2.describe_ipam_resource_discovery_associations(
        IpamResourceDiscoveryAssociationIds=[assoc_id]
    )["IpamResourceDiscoveryAssociations"]
    return associations[0]["State"] if associations else None


def _teardown_retry(fn, *, timeout_s: float = 300.0, interval_s: float = 10.0):
    """Teardown call that tolerates not-found and retries IncorrectState while a dependent
    resource is still settling."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return None
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _disassociate_and_wait(ec2, assoc_id):
    _teardown_retry(lambda: ec2.disassociate_ipam_resource_discovery(IpamResourceDiscoveryAssociationId=assoc_id))
    _poll_until(
        lambda: _teardown_retry(lambda: _association_state(ec2, assoc_id)),
        lambda s: s in (None, "disassociate-complete", "disassociate-failed"),
        timeout_s=300,
        interval_s=5,
    )


def _create_rd(ctx, ec2):
    rd_id = ec2.create_ipam_resource_discovery(
        TagSpecifications=[
            {
                "ResourceType": "ipam-resource-discovery",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-rd-")}],
            }
        ]
    )["IpamResourceDiscovery"]["IpamResourceDiscoveryId"]
    ctx.on_cleanup(
        lambda: _teardown_retry(lambda: ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id))
    )
    return rd_id


def _create_ipam(ctx, ec2):
    ipam_id = ec2.create_ipam(
        TagSpecifications=[
            {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ipam-")}]}
        ]
    )["Ipam"]["IpamId"]
    ctx.on_cleanup(lambda: _teardown_retry(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True)))
    return ipam_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
