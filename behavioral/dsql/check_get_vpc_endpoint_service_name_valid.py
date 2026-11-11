"""get-vpc-endpoint-service-name-valid."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "get-vpc-endpoint-service-name-valid"
GROUP = "data-plane"
SERVICES = ["dsql"]

_SERVICE_NAME_RE = re.compile(r"^com\.amazonaws\.[a-z0-9-]+\.dsql[a-z0-9-]*$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpcEndpointServiceName returns a well-formed PrivateLink service name for an existing cluster."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-created-with": "get-vpc-endpoint-service-name-valid"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    resp = dsql.get_vpc_endpoint_service_name(identifier=identifier)
    service_name = resp["serviceName"]
    match = _SERVICE_NAME_RE.match(service_name)
    assert match, f"expected serviceName to match {_SERVICE_NAME_RE.pattern!r}, got {service_name!r}"
    assert ctx.region in service_name, f"expected region {ctx.region} in serviceName {service_name}"

    endpoint = resp["clusterVpcEndpoint"]
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", endpoint) and endpoint.startswith(f"{identifier}."), (
        f"expected clusterVpcEndpoint to be a well-formed host named for identifier "
        f"{identifier!r}, got {endpoint!r}"
    )


def _delete_cluster(ctx, identifier):
    """Delete the unprotected cluster this check created; only an already-gone cluster is tolerated."""
    from botocore.exceptions import ClientError

    try:
        ctx.client("dsql").delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
