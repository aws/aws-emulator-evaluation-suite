"""op-contract-deprovision-ipam-pool-cidr."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags

CHECK = "op-contract-deprovision-ipam-pool-cidr"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeprovisionIpamPoolCidr deprovisions a CIDR provisioned to an IPAM pool; a CIDR never provisioned to
    the pool fails with IncorrectState and its exact message."""
    ec2 = ctx.client("ec2")

    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipam-"),
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    scopes = ec2.describe_ipam_scopes(
        Filters=[{"Name": "ipam-id", "Values": [ipam_id]}]
    )["IpamScopes"]
    private_scope = next(s for s in scopes if s["IpamScopeType"] == "private")
    scope_id = private_scope["IpamScopeId"]

    pool = ec2.create_ipam_pool(
        IpamScopeId=scope_id,
        AddressFamily="ipv4",
        TagSpecifications=[
            {
                "ResourceType": "ipam-pool",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-pool-")}],
            }
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id, Cascade=True))

    def _pool_state():
        return ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"]

    state = _poll_until(
        _pool_state, lambda s: s == "create-complete", timeout_s=60, interval_s=2,
        description="pool reaching create-complete",
    )
    assert state == "create-complete", f"pool never became create-complete, last={state}"

    octet = random.randint(10, 99)
    cidr = f"10.{octet}.0.0/16"
    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)

    def _cidr_state():
        cidrs = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id, Filters=[{"Name": "cidr", "Values": [cidr]}])[
            "IpamPoolCidrs"
        ]
        return cidrs[0]["State"] if cidrs else None

    state = _poll_until(
        _cidr_state, lambda s: s == "provisioned", timeout_s=60, interval_s=2,
        description="cidr reaching provisioned",
    )
    assert state == "provisioned", f"cidr never became provisioned, last={state}"

    # success path: deprovision the CIDR that really was provisioned
    resp = ec2.deprovision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)
    assert resp["IpamPoolCidr"]["Cidr"] == cidr, (
        f"deprovision response echoed cidr={resp['IpamPoolCidr'].get('Cidr')!r}, expected {cidr!r}"
    )

    state = _poll_until(
        _cidr_state, lambda s: s in ("deprovisioned", None), timeout_s=60, interval_s=2,
        description="cidr reaching deprovisioned",
    )
    assert state in ("deprovisioned", None), f"cidr never deprovisioned, last={state}"

    # The pool can stay briefly in a transient state after the CIDR change; wait for create-complete so
    # the next boundary sees the validation error, not a transient IncorrectState.
    state = _poll_until(
        _pool_state, lambda s: s == "create-complete", timeout_s=60, interval_s=2,
        description="pool settling back to create-complete",
    )
    assert state == "create-complete", f"pool never settled back to create-complete, last={state}"

    # Error boundary: deprovisioning a CIDR never provisioned to this pool fails with IncorrectState,
    # since no provisioned CIDR exists to release.
    other_cidr = f"172.{random.randint(16, 31)}.0.0/16"

    error = _error(lambda: ec2.deprovision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=other_cidr))
    assert error["Code"] == "IncorrectState", error
    assert error.get("Message") == f"The specified action is not valid.The pool CIDR {other_cidr} does not exist.", error


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
