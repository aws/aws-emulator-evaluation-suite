"""domain-tag-lifecycle-add-list-remove."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-tag-lifecycle-add-list-remove"
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
    """AddTags on a domain is additive, ListTags reflects every added key exactly, and
    RemoveTags deletes only the named key, leaving the other tag intact.
    """
    es = ctx.client("es")
    domain_name = ctx.unique_name("sim2real-behav-es-")[:28].rstrip("-")
    domain = _retry_throttled(lambda: es.create_elasticsearch_domain(
        DomainName=domain_name,
        ElasticsearchVersion="7.10",
        ElasticsearchClusterConfig={"InstanceType": "t3.small.elasticsearch", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    ))["DomainStatus"]
    ctx.on_cleanup(lambda: es.delete_elasticsearch_domain(DomainName=domain_name))
    arn = domain["ARN"]

    initial = es.list_tags(ARN=arn)["TagList"]
    assert initial == [], f"a freshly created domain should have no tags, got {initial!r}"

    es.add_tags(ARN=arn, TagList=[
        {"Key": "sim2real-owner", "Value": "check"},
        {"Key": "sim2real-env", "Value": "test"},
    ])
    after_add = {t["Key"]: t["Value"] for t in es.list_tags(ARN=arn)["TagList"]}
    assert after_add == {"sim2real-owner": "check", "sim2real-env": "test"}, (
        f"expected both tags present after AddTags, got {after_add!r}"
    )

    es.remove_tags(ARN=arn, TagKeys=["sim2real-env"])
    after_remove = {t["Key"]: t["Value"] for t in es.list_tags(ARN=arn)["TagList"]}
    assert after_remove == {"sim2real-owner": "check"}, (
        f"RemoveTags should delete only 'sim2real-env', got {after_remove!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
