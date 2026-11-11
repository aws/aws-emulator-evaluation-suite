"""get-compatible-versions-reflects-created-domain-version."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-compatible-versions-reflects-created-domain-version"
GROUP = 'domain-lifecycle'
SERVICES = ['es']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _retry_throttled(fn, attempts: int = 8):
    """Call ``fn()``, retrying with backoff only on a throttle response."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == attempts - 1:
                raise
            time.sleep(4.0 * (1 + attempt) + random.uniform(0, 3.0))


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleElasticsearchVersions, scoped to a domain this check created, names
    that domain's own version as the SourceVersion and offers only OpenSearch upgrade
    targets for a legacy 7.10 domain, never a lower or equal Elasticsearch version.
    """
    es = ctx.client("es")
    domain_name = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")
    _retry_throttled(lambda: es.create_elasticsearch_domain(
        DomainName=domain_name,
        ElasticsearchVersion="7.10",
        ElasticsearchClusterConfig={"InstanceType": "t3.small.elasticsearch", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    ))
    ctx.on_cleanup(lambda: es.delete_elasticsearch_domain(DomainName=domain_name))

    rows = es.get_compatible_elasticsearch_versions(DomainName=domain_name)[
        "CompatibleElasticsearchVersions"
    ]
    assert len(rows) == 1, f"expected exactly one row scoped to our domain, got {rows!r}"
    row = rows[0]
    assert row["SourceVersion"] == "7.10", (
        f"SourceVersion should be our domain's own version '7.10', got {row['SourceVersion']!r}"
    )
    targets = row["TargetVersions"]
    assert targets, f"a 7.10 domain should offer at least one upgrade target, got {targets!r}"
    assert all(t.startswith("OpenSearch_") for t in targets), (
        f"every upgrade target from legacy 7.10 should be an OpenSearch_* version, got {targets!r}"
    )
    assert "7.10" not in targets, "the domain's own current version must not appear as a target"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
