"""batchget-vpc-endpoint-partial-not-found-error."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "batchget-vpc-endpoint-partial-not-found-error"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

_FAKE_VPCE_ID = "vpce-" + "0" * 17


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control",
      "resource:account-singleton:aoss-vpc-endpoint")
def run(ctx) -> None:
    """BatchGetVpcEndpoint with a mix of a real id and an unknown id returns the real one in
    vpcEndpointDetails and a per-item NOT_FOUND entry in vpcEndpointErrorDetails."""
    aoss = ctx.client("opensearchserverless")
    tag_value = _short_name(ctx, "sim2real-bgvpce")
    # The run's shared network has the DNS support and hostnames a private-DNS endpoint requires.
    net = ctx.network()
    vpc_id, subnet_id = net.vpc_id, net.subnet_ids[0]

    created = aoss.create_vpc_endpoint(
        name=tag_value, vpcId=vpc_id, subnetIds=[subnet_id]
    )["createVpcEndpointDetail"]
    endpoint_id = created["id"]
    ctx.on_cleanup(lambda: _cleanup_endpoint(ctx, endpoint_id))

    resp = aoss.batch_get_vpc_endpoint(ids=[endpoint_id, _FAKE_VPCE_ID])
    details = resp.get("vpcEndpointDetails", [])
    errors = resp.get("vpcEndpointErrorDetails", [])

    assert len(details) == 1, f"expected exactly one successful item, got {details}"
    assert details[0]["id"] == endpoint_id, (
        f"expected the successful item to be {endpoint_id!r}, got {details[0]['id']!r}"
    )

    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["id"] == _FAKE_VPCE_ID, (
        f"expected the per-item error to name {_FAKE_VPCE_ID!r}, got {errors[0]['id']!r}"
    )
    assert errors[0]["errorCode"] == "NOT_FOUND", (
        f"expected errorCode 'NOT_FOUND' for the never-created id, got {errors[0]['errorCode']!r}"
    )


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _cleanup_endpoint(ctx, endpoint_id: str) -> None:
    aoss = ctx.client("opensearchserverless")

    def probe():
        resp = aoss.batch_get_vpc_endpoint(ids=[endpoint_id])
        details = resp.get("vpcEndpointDetails", [])
        return details[0]["status"] if details else "GONE"

    status = _poll_until(probe, lambda s: s in ("ACTIVE", "FAILED", "GONE"), timeout_s=600, interval_s=15)
    if status == "GONE":
        return
    if status not in ("ACTIVE", "FAILED"):
        raise AssertionError(f"VPC endpoint {endpoint_id} still {status} after 600s; not deleted")
    aoss.delete_vpc_endpoint(id=endpoint_id)
    status = _poll_until(probe, lambda s: s == "GONE", timeout_s=600, interval_s=15)
    if status != "GONE":
        raise AssertionError(f"VPC endpoint {endpoint_id} still {status} 600s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
