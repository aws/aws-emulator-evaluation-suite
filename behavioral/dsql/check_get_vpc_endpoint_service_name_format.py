"""get-vpc-endpoint-service-name-format."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-vpc-endpoint-service-name-format"
GROUP = "state"
SERVICES = ["dsql"]

_SERVICE_NAME_RE = re.compile(r"^com\.amazonaws\.[a-z0-9-]+\.dsql[a-z0-9-]*$")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpcEndpointServiceName on a real, ACTIVE cluster returns a serviceName that matches the
    documented com.amazonaws.<region>.dsql* naming convention for the target region."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "get-vpc-endpoint-service-name-format"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)

    resp = dsql.get_vpc_endpoint_service_name(identifier=identifier)
    service_name = resp["serviceName"]
    expected_region = f"com.amazonaws.{ctx.region}.dsql*"
    assert _SERVICE_NAME_RE.match(service_name), (
        f"expected serviceName to match {expected_region!r} convention, got {service_name!r}"
    )
    assert f".{ctx.region}." in service_name, (
        f"expected region {ctx.region!r} in serviceName, got {service_name!r}"
    )

    resp_again = dsql.get_vpc_endpoint_service_name(identifier=identifier)
    assert resp_again["serviceName"] == service_name, (
        f"expected serviceName to be stable across reads, got {service_name!r} then "
        f"{resp_again['serviceName']!r}"
    )


def _wait_for_status(dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
