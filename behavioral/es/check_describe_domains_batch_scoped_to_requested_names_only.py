"""describe-domains-batch-scoped-to-requested-names-only."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-domains-batch-scoped-to-requested-names-only"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeElasticsearchDomains with two domain names this check created returns
    exactly those two, regardless of how many other domains the account holds.
    """
    es = ctx.client("es")
    name_a = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")
    name_b = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")

    for name in (name_a, name_b):
        _retry_throttled(lambda name=name: es.create_elasticsearch_domain(
            DomainName=name,
            ElasticsearchVersion="7.10",
            ElasticsearchClusterConfig={"InstanceType": "t3.small.elasticsearch", "InstanceCount": 1},
            EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        ))
        ctx.on_cleanup(lambda name=name: es.delete_elasticsearch_domain(DomainName=name))

    rows = es.describe_elasticsearch_domains(DomainNames=[name_a, name_b])["DomainStatusList"]
    seen = {r["DomainName"] for r in rows}
    assert seen == {name_a, name_b}, (
        f"expected exactly {{{name_a!r}, {name_b!r}}}, got {seen!r}"
    )

    single = es.describe_elasticsearch_domains(DomainNames=[name_a])["DomainStatusList"]
    assert [r["DomainName"] for r in single] == [name_a], (
        f"a single-name batch should return only that domain, got {single!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
