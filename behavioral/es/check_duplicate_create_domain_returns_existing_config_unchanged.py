"""duplicate-create-domain-returns-existing-config-unchanged."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-create-domain-returns-existing-config-unchanged"
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


def _access_policy(ctx, domain_name: str) -> str:
    import json as _json

    arn = f"arn:aws:es:{ctx.region}:{ctx.account}:domain/{domain_name}"
    return _json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateElasticsearchDomain naming an existing domain answers 200 with the
    FIRST call's cluster config, silently ignoring a differing InstanceCount in the retry.
    """
    es = ctx.client("es")
    name = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")

    first = _retry_throttled(lambda: es.create_elasticsearch_domain(
        DomainName=name,
        ElasticsearchVersion="7.10",
        ElasticsearchClusterConfig={"InstanceType": "t3.small.elasticsearch", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        AccessPolicies=_access_policy(ctx, name),
    ))
    ctx.on_cleanup(lambda: es.delete_elasticsearch_domain(DomainName=name))
    assert first["DomainStatus"]["ElasticsearchClusterConfig"]["InstanceCount"] == 1, (
        f"first create reported InstanceCount "
        f"{first['DomainStatus']['ElasticsearchClusterConfig']['InstanceCount']!r}, expected 1"
    )

    second = _retry_throttled(lambda: es.create_elasticsearch_domain(
        DomainName=name,
        ElasticsearchVersion="7.10",
        ElasticsearchClusterConfig={"InstanceType": "t3.small.elasticsearch", "InstanceCount": 2},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        AccessPolicies=_access_policy(ctx, name),
    ))
    second_count = second["DomainStatus"]["ElasticsearchClusterConfig"]["InstanceCount"]
    assert second_count == 1, (
        f"a duplicate create naming InstanceCount=2 should answer with the original "
        f"InstanceCount=1 unchanged, got {second_count!r}"
    )

    described = es.describe_elasticsearch_domain(DomainName=name)
    described_count = described["DomainStatus"]["ElasticsearchClusterConfig"]["InstanceCount"]
    assert described_count == 1, (
        f"a later DescribeElasticsearchDomain should still show InstanceCount=1, "
        f"got {described_count!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
