"""service-network-service-association-propagates-dns-and-clears."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-network-service-association-propagates-dns-and-clears"
GROUP = 'association-lifecycle'
SERVICES = ['vpc-lattice']


def _unless_gone(fn):
    """A teardown that treats ResourceNotFoundException as done: the check deletes these itself."""
    def go():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    return go


def _all(fn, key, **kw):
    """Page a Lattice List* fully; other resources in the account can push ours off page one."""
    out, token = [], None
    while True:
        page = fn(**kw, nextToken=token) if token else fn(**kw)
        out.extend(page.get(key, []))
        token = page.get("nextToken")
        if not token:
            return out


def _poll(get, want, budget, what):
    seen = []
    deadline = time.time() + budget
    while True:
        seen.append(get())
        if seen[-1] == want:
            return seen
        assert time.time() < deadline, f"{what}; the statuses seen were {seen[-8:]!r}"
        time.sleep(3)


@tags("concern:representation", "axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A service network service association goes CREATE_IN_PROGRESS -> ACTIVE, reports the DNS name the
    service minted and the service's ARN, is listed by the network, and is gone from that list after
    deletion.
    """
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "vpc-lattice-association-lifecycle"}

    net = vl.create_service_network(name=ctx.unique_name("sim2real-latt-sn-"), authType="NONE", tags=kv)
    ctx.on_cleanup(_unless_gone(
        lambda i=net["id"]: vl.delete_service_network(serviceNetworkIdentifier=i)))

    svc = vl.create_service(name=ctx.unique_name("sim2real-latt-svc-"), authType="NONE", tags=kv)
    ctx.on_cleanup(_unless_gone(lambda i=svc["id"]: vl.delete_service(serviceIdentifier=i)))

    # A service is born CREATE_IN_PROGRESS and Lattice refuses every mutation (including Delete)
    # until it settles, so waiting here is what makes the teardown above able to run at all.
    _poll(lambda: vl.get_service(serviceIdentifier=svc["id"])["status"], "ACTIVE", 300,
          f"service {svc['id']} never reached ACTIVE")

    minted = svc["dnsEntry"]["domainName"]
    assert re.fullmatch(r"[A-Za-z0-9.-]+", minted) and "." in minted, (
        f"CreateService minted domain {minted!r}, which is not a well-formed DNS name"
    )

    assoc = vl.create_service_network_service_association(
        serviceNetworkIdentifier=net["id"], serviceIdentifier=svc["id"], tags=kv
    )
    ctx.on_cleanup(_unless_gone(
        lambda i=assoc["id"]: vl.delete_service_network_service_association(
            serviceNetworkServiceAssociationIdentifier=i
        )
    ))
    assert assoc["status"] == "CREATE_IN_PROGRESS", (
        f"the association was born {assoc['status']!r}; Lattice reports CREATE_IN_PROGRESS and "
        f"an emulator that returns ACTIVE synchronously hides the transition entirely"
    )

    _poll(
        lambda: vl.get_service_network_service_association(
            serviceNetworkServiceAssociationIdentifier=assoc["id"]
        )["status"],
        "ACTIVE", 300,
        f"association {assoc['id']} never reached ACTIVE",
    )

    settled = vl.get_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc["id"]
    )
    assert settled["dnsEntry"]["domainName"] == minted, (
        f"the association publishes {settled['dnsEntry']['domainName']!r} but the service minted "
        f"{minted!r} — the association must surface the service's own name, not a second one"
    )
    assert settled["serviceArn"] == svc["arn"], (
        f"the association points at {settled['serviceArn']!r}, not the service {svc['arn']!r} "
        f"it was created for"
    )

    listed = {
        a["id"]
        for a in _all(
            vl.list_service_network_service_associations,
            "items", serviceNetworkIdentifier=net["id"],
        )
    }
    assert listed == {assoc["id"]}, (
        f"the service network lists associations {sorted(listed)!r}; it was created in this check "
        f"and must hold exactly the one association {assoc['id']!r}"
    )

    vl.delete_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc["id"]
    )
    deadline = time.time() + 300
    while True:
        remaining = {
            a["id"]
            for a in _all(
                vl.list_service_network_service_associations,
                "items", serviceNetworkIdentifier=net["id"],
            )
        }
        if assoc["id"] not in remaining:
            break
        assert time.time() < deadline, (
            f"association {assoc['id']!r} was deleted but the service network still lists "
            f"{sorted(remaining)!r}"
        )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
