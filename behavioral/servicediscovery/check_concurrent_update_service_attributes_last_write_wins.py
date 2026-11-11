"""concurrent-update-service-attributes-last-write-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-service-attributes-last-write-wins"
GROUP = "concurrency"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateServiceAttributes calls setting one key to "red" and "blue" both succeed,
    and the value that lands is exactly one of the two, unchanged on a second read."""
    sd = ctx.client("servicediscovery")
    ns_id = _create_http_namespace(ctx, sd)
    svc_id = _create_http_service(ctx, sd, ns_id)

    sd.update_service_attributes(ServiceId=svc_id, Attributes={"color": "seed"})

    def writer(value):
        sd.update_service_attributes(ServiceId=svc_id, Attributes={"color": value})
        return value

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(writer, value) for value in ("red", "blue")]
        outcomes = [f.result() for f in futures]  # raises if either racer got an error

    assert set(outcomes) == {"red", "blue"}, f"expected both racers to complete, got {outcomes!r}"

    final = sd.get_service_attributes(ServiceId=svc_id)["ServiceAttributes"]["Attributes"]["color"]
    assert final in ("red", "blue"), f"unexpected merged/corrupted value: {final!r}"

    again = sd.get_service_attributes(ServiceId=svc_id)["ServiceAttributes"]["Attributes"]["color"]
    assert again == final, "settled attribute value must be stable across reads"


def _wait_operation(sd, operation_id, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            break
        time.sleep(interval_s)
    if op is None or op["Status"] != "SUCCESS":
        raise AssertionError(f"operation {operation_id} did not reach SUCCESS: {op}")
    return op


def _create_http_namespace(ctx, sd):
    resp = sd.create_http_namespace(
        Name=ctx.unique_name("sim2real-httpns-"),
        Tags=[{"Key": "sim2real-audit", "Value": "true"}],
    )
    op = _wait_operation(sd, resp["OperationId"])
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=ns_id))
    return ns_id


def _create_http_service(ctx, sd, ns_id):
    svc = sd.create_service(
        Name=ctx.unique_name("sim2real-httpsvc-"),
        NamespaceId=ns_id,
        Type="HTTP",
        Tags=[{"Key": "sim2real-audit", "Value": "true"}],
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: sd.delete_service(Id=svc_id))
    return svc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
