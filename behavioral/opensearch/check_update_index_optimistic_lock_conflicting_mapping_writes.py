"""update-index-optimistic-lock-conflicting-mapping-writes."""
from __future__ import annotations

import json
import random
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

_THROTTLE_CODES = {"LimitExceededException", "TooManyRequestsException", "ThrottlingException"}

CHECK = "update-index-optimistic-lock-conflicting-mapping-writes"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateIndex calls that define the SAME new field with incompatible types
    resolve deterministically: exactly one wins, the other is rejected, and GetIndex reflects a
    single consistent field type -- never a corrupted mix of both."""
    opensearch = ctx.client("opensearch")
    domain_name = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, domain_name)

    index_name = "sim2real-idx-race"
    opensearch.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"title": {"type": "text"}}}},
    )
    ctx.on_cleanup(lambda: opensearch.delete_index(DomainName=domain_name, IndexName=index_name))

    def _update(field_type: str):
        return opensearch.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"mappings": {"properties": {"score": {"type": field_type}}}},
        )

    results: list[tuple[str, object]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(_update, "integer"): "integer", pool.submit(_update, "keyword"): "keyword"}
        for future, field_type in futures.items():
            try:
                results.append((field_type, ("ok", future.result())))
            except Exception as exc:  # noqa: BLE001 - captured for the assertion below
                results.append((field_type, ("error", exc)))

    successes = [r for r in results if r[1][0] == "ok"]
    failures = [r for r in results if r[1][0] == "error"]
    assert len(successes) == 1, f"expected exactly one racer to win, got {len(successes)}: {results!r}"
    assert len(failures) == 1, f"expected exactly one racer to lose, got {len(failures)}: {results!r}"

    from botocore.exceptions import ClientError

    failure_exc = failures[0][1][1]
    assert isinstance(failure_exc, ClientError), f"expected a ClientError, got {failure_exc!r}"
    error = failure_exc.response["Error"]
    code, message = error["Code"], error.get("Message", "")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"

    # GetIndex reflects a single consistent type -- whichever racer actually won, never a mix
    winning_type = successes[0][0]
    schema = json.dumps(opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"])
    assert _field_type(schema, "score") == winning_type, (
        f"GetIndex shows score:{_field_type(schema, 'score')!r}, expected the winning racer's "
        f"type {winning_type!r}"
    )


def _field_type(schema_json: str, field: str) -> str | None:
    try:
        obj = json.loads(schema_json)
    except json.JSONDecodeError:
        return None

    def _search(node):
        if isinstance(node, dict):
            if "properties" in node and isinstance(node["properties"], dict) and field in node["properties"]:
                return node["properties"][field].get("type")
            for value in node.values():
                found = _search(value)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = _search(item)
                if found:
                    return found
        return None

    return _search(obj)


def _create_minimal_domain(ctx) -> str:
    opensearch = ctx.client("opensearch")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-osd-").replace("_", "-").lower()[:28]
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{name}"
    # A wildcard Principal is rejected outright ("Enable fine-grained access control or apply a
    # restrictive access policy to your domain"); scope the resource policy to this account instead.
    access_policy = json.dumps(
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
    )
    from botocore.exceptions import ClientError as _ClientError

    for attempt in range(12):
        try:
            opensearch.create_domain(
                DomainName=name,
                # CreateIndex/UpdateIndex/GetIndex require the automatic-semantic-enrichment
                # feature, which OpenSearch_2.11 does not carry.
                EngineVersion="OpenSearch_2.19",
                ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
                EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
                AccessPolicies=access_policy,
                TagList=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except _ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
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
