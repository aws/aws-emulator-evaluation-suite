"""version-catalog-listing."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "version-catalog-listing"
GROUP = 'catalog'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _create_domain(ctx, osc, domain_name) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(TagList=[{"Key": "env", "Value": "test"}], **kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListVersions includes an OpenSearch_* entry and OpenSearch_2.11, the version a domain
    created here reports; the domain proves the advertised version is provisionable."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)

    described = osc.describe_domain(DomainName=domain)["DomainStatus"]
    assert described["EngineVersion"] == ENGINE_VERSION, (
        f"expected the domain to be provisioned with {ENGINE_VERSION}, "
        f"got {described['EngineVersion']}"
    )

    resp = osc.list_versions()
    versions = resp["Versions"]
    assert len(versions) > 0, "expected a non-empty version catalog"
    assert any(v.startswith("OpenSearch_") for v in versions), (
        f"expected at least one OpenSearch_* version, got {versions}"
    )
    assert "OpenSearch_2.11" in versions, f"expected OpenSearch_2.11 in catalog, got {versions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
