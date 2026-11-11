"""deleting-a-service-network-is-rejected-while-an-association-survives-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-a-service-network-is-rejected-while-an-association-survives-it"
GROUP = 'lattice-lifecycle'
SERVICES = ['vpc-lattice']

_SCENARIO = 'vpcl-sn-association-guard'

# Codes that mean "already gone" on a delete, so the cleanup has nothing left to do. Held in a
# name rather than an inline tuple: these are teardown idempotence, never an assertion.
_GONE = frozenset({"ResourceNotFoundException", "NotFoundException"})


def _error_code(exc):
    return exc.response.get("Error", {}).get("Code")


def _eventual(fn, what, retry_code, budget=300):
    """A cleanup that retries `fn` while AWS answers `retry_code`, then declares the leak.

    Lattice teardown has real ordering dependencies -- a service network cannot be deleted while an
    association survives it, which is the very fact this check asserts -- and they clear on the
    service's own clock. Retrying is the wait; the raise is what stops a stranded resource
    from looking like a clean run.
    """
    def _go():
        deadline = time.time() + budget
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                if _error_code(exc) in _GONE:
                    return
                if _error_code(exc) != retry_code or time.time() > deadline:
                    raise RuntimeError(
                        f"could not delete {what}: {_error_code(exc)} {exc}"
                    ) from exc
                time.sleep(10)
    return _go


def _await_status(status_of, what, budget=300):
    """Poll a `() -> status` callable to ACTIVE.

    Lattice refuses most operations on a resource that is still CREATE_IN_PROGRESS, so the status
    is a real precondition rather than a nicety -- and CREATE_IN_PROGRESS is the ONLY other status
    tolerated here, so a CREATE_FAILED fails the check immediately instead of timing out.
    """
    deadline = time.time() + budget
    seen = []
    while True:
        seen.append(status_of())
        if seen[-1] == "ACTIVE":
            return seen
        assert seen[-1] == "CREATE_IN_PROGRESS" and time.time() < deadline, (
            f"{what} never became ACTIVE: statuses were {seen[-8:]!r}")
        time.sleep(5)


def _await_gone(getter, what, budget=300):
    """Poll until `getter` raises ResourceNotFoundException, i.e. the resource is really gone.

    A Lattice delete returns immediately and the resource then sits in DELETE_IN_PROGRESS, so
    "the API accepted the delete" is not the same fact as "nothing is associated any more".
    """
    deadline = time.time() + budget
    seen = []
    while True:
        try:
            seen.append(getter()["status"])
        except ClientError as exc:
            if _error_code(exc) == "ResourceNotFoundException":
                return seen
            raise
        assert seen[-1] == "DELETE_IN_PROGRESS" and time.time() < deadline, (
            f"{what} never disappeared: statuses were {seen[-8:]!r}")
        time.sleep(5)


# ===== the check =====


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DeleteServiceNetwork fails with ConflictException and the exact message while an association
    is ACTIVE, leaving one associated service; once the association is gone the same delete succeeds
    and GetServiceNetwork fails with ResourceNotFoundException and the exact message.
    """
    lat = ctx.client("vpc-lattice")
    tagmap = {"sim2real": _SCENARIO}

    sn = lat.create_service_network(name=ctx.unique_name("sim2real-vpclg-sn-"), authType="NONE",
                                   tags=tagmap)
    ctx.on_cleanup(_eventual(
        lambda: lat.delete_service_network(serviceNetworkIdentifier=sn["id"]),
        f"service network {sn['id']}", "ConflictException"))
    svc = lat.create_service(name=ctx.unique_name("sim2real-vpclg-svc-"), authType="NONE",
                             tags=tagmap)
    ctx.on_cleanup(_eventual(lambda: lat.delete_service(serviceIdentifier=svc["id"]),
                             f"service {svc['id']}", "ConflictException"))
    _await_status(lambda: lat.get_service(serviceIdentifier=svc["id"])["status"],
                  f"service {svc['id']}")

    assoc = lat.create_service_network_service_association(
        serviceNetworkIdentifier=sn["id"], serviceIdentifier=svc["id"], tags=tagmap)["id"]
    ctx.on_cleanup(_eventual(
        lambda: lat.delete_service_network_service_association(
            serviceNetworkServiceAssociationIdentifier=assoc),
        f"service association {assoc}", "ConflictException"))
    _await_status(lambda: lat.get_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc)["status"], f"association {assoc}")

    # The negative arm: the association is the only thing standing in the way.
    try:
        lat.delete_service_network(serviceNetworkIdentifier=sn["id"])
    except ClientError as exc:
        refusal = _error_code(exc)
        refusal_message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"DeleteServiceNetwork was ACCEPTED for {sn['id']} while association {assoc} was "
            f"still ACTIVE, so the association guards nothing")
    assert refusal == "ConflictException", (
        f"DeleteServiceNetwork was refused for the wrong reason while an association was live: "
        f"{refusal!r}")
    expected = f"ServiceNetwork {sn['id']} has service(s) associated"
    assert refusal_message == expected, (
        f"the ConflictException message is {refusal_message!r}; real AWS says {expected!r}")

    # The refused delete must not have applied in part: the service network is still readable,
    # still the same resource, and still counting the association.
    still = lat.get_service_network(serviceNetworkIdentifier=sn["id"])
    assert still["arn"] == sn["arn"], (
        f"the refused delete changed the service network's identity: {still!r} was {sn!r}")
    assert still["numberOfAssociatedServices"] == 1, (
        f"the service network does not count the association that just guarded it: {still!r}")

    # The positive control: remove the only association, wait until it is really gone, and the
    # identical delete is accepted. The bounded retry covers the DELETE_IN_PROGRESS window the
    # association's own status does not close -- it never turns a refusal into a pass, because a
    # refusal that outlives the budget fails the check.
    lat.delete_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc)
    _await_gone(lambda: lat.get_service_network_service_association(
        serviceNetworkServiceAssociationIdentifier=assoc), f"association {assoc}")
    deadline = time.time() + 180
    while True:
        try:
            lat.delete_service_network(serviceNetworkIdentifier=sn["id"])
            break
        except ClientError as exc:
            assert _error_code(exc) == "ConflictException" and time.time() < deadline, (
                f"DeleteServiceNetwork was still refused after its last association was gone: "
                f"{_error_code(exc)} {exc}")
            time.sleep(5)
    try:
        gone = lat.get_service_network(serviceNetworkIdentifier=sn["id"])
    except ClientError as exc:
        assert _error_code(exc) == "ResourceNotFoundException", (
            f"reading the deleted service network failed for the wrong reason: {exc}")
        expected = f"ServiceNetwork {sn['id']} cannot be found."
        message = exc.response.get("Error", {}).get("Message")
        assert message == expected, (
            f"the ResourceNotFoundException message is {message!r}; real AWS says {expected!r}")
    else:
        raise AssertionError(
            f"the accepted DeleteServiceNetwork left {sn['id']} readable: {gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
