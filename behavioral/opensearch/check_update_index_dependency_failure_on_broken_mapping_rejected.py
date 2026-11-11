"""update-index-dependency-failure-on-broken-mapping-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-index-dependency-failure-on-broken-mapping-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex with a mapping that names an undefined analyzer fails with ValidationException and its exact
    message and adds no field, while a valid UpdateIndex reports UPDATED and its field persists.
    """
    opensearch = ctx.client("opensearch")
    domain_name = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, domain_name)

    index_name = "sim2real-idx"
    opensearch.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"title": {"type": "text"}}}},
    )
    ctx.on_cleanup(lambda: opensearch.delete_index(DomainName=domain_name, IndexName=index_name))

    before = json.dumps(opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"])
    assert "title" in before, f"expected the 'title' field in the freshly created index schema, got {before!r}"

    code, message = _error_detail(
        lambda: opensearch.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={
                "mappings": {
                    "properties": {"body": {"type": "text", "analyzer": "sim2real_missing_analyzer"}}
                }
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "analyzer [sim2real_missing_analyzer] has not been configured in mappings"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the broken field must not have been applied
    after_broken = json.dumps(opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"])
    assert "sim2real_missing_analyzer" not in after_broken, (
        f"rejected UpdateIndex leaked the missing analyzer name into the schema: {after_broken!r}"
    )
    assert "\"body\"" not in after_broken, f"rejected UpdateIndex's 'body' field landed anyway: {after_broken!r}"

    # positive control: a valid mapping update on the same index still succeeds
    status = opensearch.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"tags": {"type": "keyword"}}}},
    )["Status"]
    assert status == "UPDATED", f"expected the valid positive-control UpdateIndex to report Status=UPDATED, got {status!r}"

    after_valid = json.dumps(opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"])
    assert "tags" in after_valid, f"positive-control UpdateIndex's 'tags' field never persisted: {after_valid!r}"


def _error_detail(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_domain(ctx) -> str:
    opensearch = ctx.client("opensearch")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-osd-").replace("_", "-").lower()[:28]
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{name}"
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "es:*",
                        "Resource": f"{domain_arn}/*",
                    }
                ],
            }
        ),
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=name))
    return name


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1500.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} did not become active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
