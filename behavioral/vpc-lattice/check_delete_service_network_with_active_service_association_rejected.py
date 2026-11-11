"""delete-service-network-with-active-service-association-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-service-network-with-active-service-association-rejected"
GROUP = 'association-rejected'
SERVICES = ['vpc-lattice']


def _error(fn):
    """The AWS error code and message fn() raised.

    Raises when the call SUCCEEDS: an emulator accepting input real AWS refuses is the strongest
    signal this check can produce, and returning a falsy sentinel would disguise it as a mismatched
    error code.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        "the call SUCCEEDED where real AWS refuses it — the guard under test is absent"
    )


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
    out, token = [], None
    while True:
        page = fn(**kw, nextToken=token) if token else fn(**kw)
        out.extend(page.get(key, []))
        token = page.get("nextToken")
        if not token:
            return out


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """DeleteServiceNetwork with an active service association fails with ConflictException and the exact
    message, and the network and its association survive; once the association is deleted, the network
    deletes and GetServiceNetwork fails with ResourceNotFoundException and the exact message.
    """
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "vpc-lattice-delete-guard"}

    net = vl.create_service_network(name=ctx.unique_name("sim2real-latt-sn-"), authType="NONE", tags=kv)
    ctx.on_cleanup(_unless_gone(
        lambda i=net["id"]: vl.delete_service_network(serviceNetworkIdentifier=i)))

    svc = vl.create_service(name=ctx.unique_name("sim2real-latt-svc-"), authType="NONE", tags=kv)
    ctx.on_cleanup(_unless_gone(lambda i=svc["id"]: vl.delete_service(serviceIdentifier=i)))

    # A service is born CREATE_IN_PROGRESS and Lattice refuses every mutation until it settles, so
    # waiting here is what makes the teardown above able to run at all.
    deadline = time.time() + 300
    while True:
        svc_status = vl.get_service(serviceIdentifier=svc["id"])["status"]
        if svc_status == "ACTIVE":
            break
        assert svc_status == "CREATE_IN_PROGRESS" and time.time() < deadline, (
            f"service {svc['id']} never reached ACTIVE: status={svc_status!r}"
        )
        time.sleep(3)

    assoc = vl.create_service_network_service_association(
        serviceNetworkIdentifier=net["id"], serviceIdentifier=svc["id"], tags=kv
    )
    ctx.on_cleanup(_unless_gone(
        lambda i=assoc["id"]: vl.delete_service_network_service_association(
            serviceNetworkServiceAssociationIdentifier=i
        )
    ))

    deadline = time.time() + 300
    while True:
        status = vl.get_service_network_service_association(
            serviceNetworkServiceAssociationIdentifier=assoc["id"]
        )["status"]
        if status == "ACTIVE":
            break
        assert status == "CREATE_IN_PROGRESS" and time.time() < deadline, (
            f"the association never reached ACTIVE, so the guard below would be untested: "
            f"status={status!r}"
        )
        time.sleep(3)

    code, message = _error(lambda: vl.delete_service_network(serviceNetworkIdentifier=net["id"]))
    assert code == "ConflictException", (
        f"deleting a service network with an active service association raised {code!r}; "
        f"real AWS raises ConflictException"
    )
    expected = f"ServiceNetwork {net['id']} has service(s) associated"
    assert message == expected, (
        f"the ConflictException message is {message!r}; real AWS says {expected!r}"
    )

    survived = vl.get_service_network(serviceNetworkIdentifier=net["id"])
    assert survived["arn"] == net["arn"], (
        f"the refused delete returned the wrong service network: {survived['arn']!r} != "
        f"{net['arn']!r}"
    )
    still_there = {
        a["id"]
        for a in _all(
            vl.list_service_network_service_associations,
            "items", serviceNetworkIdentifier=net["id"],
        )
    }
    assert still_there == {assoc["id"]}, (
        f"the refused delete disturbed the associations: the service network now lists "
        f"{sorted(still_there)!r}, expected only {assoc['id']!r}"
    )

    vl.delete_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc["id"]
    )
    deadline = time.time() + 300
    while True:
        if not _all(
            vl.list_service_network_service_associations,
            "items", serviceNetworkIdentifier=net["id"],
        ):
            break
        assert time.time() < deadline, (
            f"the association {assoc['id']!r} never cleared, so the positive control below "
            f"cannot distinguish a permanent refusal from a correct guard"
        )
        time.sleep(5)

    # Positive control: the identical call now succeeds, so the refusal above was the association
    # and not a service network that can never be deleted.
    vl.delete_service_network(serviceNetworkIdentifier=net["id"])
    gone, message = _error(lambda: vl.get_service_network(serviceNetworkIdentifier=net["id"]))
    assert gone == "ResourceNotFoundException", (
        f"after a successful delete, reading the service network raised {gone!r}; "
        f"real AWS raises ResourceNotFoundException"
    )
    expected = f"ServiceNetwork {net['id']} cannot be found."
    assert message == expected, (
        f"the ResourceNotFoundException message is {message!r}; real AWS says {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
