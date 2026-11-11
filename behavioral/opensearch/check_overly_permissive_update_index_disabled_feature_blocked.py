"""overly-permissive-update-index-disabled-feature-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-update-index-disabled-feature-blocked"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIndex on an ACTIVE Elasticsearch_7.10 domain fails with ValidationException and its exact
    message, GetIndex for that index fails the same way, and DescribeDomain still resolves the domain.
    """
    os_client = ctx.client("opensearch")

    domain_name = _short_name(ctx, "sim2real-noidx-")
    os_client.create_domain(
        DomainName=domain_name,
        EngineVersion="Elasticsearch_7.10",
        ClusterConfig={
            # `t3.small.search`, not the retired `t3.small.elasticsearch` spelling, which CreateDomain
            # refuses with ValidationException; Elasticsearch_7.10 is offered with t3.small.search.
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: os_client.delete_domain(DomainName=domain_name))
    # The domain must be genuinely ACTIVE, not merely VISIBLE, before the index-management calls:
    # while DomainProcessingStatus is still Creating, UpdateIndex answers with a 500-class
    # InternalException that says nothing about the feature gate this check is about.
    _wait_domain_active(os_client, domain_name)

    index_name = "sim2realidx"
    schema = {"mappings": {"properties": {"title": {"type": "text"}}}}

    update_code, update_message = _error_code(
        lambda: os_client.update_index(
            DomainName=domain_name, IndexName=index_name, IndexSchema=schema
        )
    )
    assert update_code == "ValidationException", (
        f"expected ValidationException for UpdateIndex on an engine that doesn't support "
        f"index management, got {update_code}"
    )
    gated = "Automatic Semantic Enrichment feature is not supported on this software version."
    assert update_message == gated, f"UpdateIndex ValidationException message {update_message!r}"

    get_code, get_message = _error_code(
        lambda: os_client.get_index(DomainName=domain_name, IndexName=index_name)
    )
    assert get_code == "ValidationException", (
        f"expected the index-management feature gate to also block GetIndex, confirming no "
        f"index was ever created as a side effect, got {get_code}"
    )
    assert get_message == gated, f"GetIndex ValidationException message {get_message!r}"

    described = os_client.describe_domain(DomainName=domain_name)
    assert described["DomainStatus"]["DomainName"] == domain_name


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _short_name(ctx, prefix, max_len=28):
    name = ctx.unique_name(prefix)[:max_len]
    if not name[-1].isalnum():
        name = name[:-1] + "0"
    return name


def _wait_domain_active(client, domain_name, timeout_s=1800.0, interval_s=20.0):
    """Poll until the domain is Created, no longer Processing and has published an Endpoint.

    Domain creation typically takes 680-850 s, so the bound is generous rather than tight.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(interval_s)
            continue
        last = {k: status.get(k) for k in ("Created", "Processing", "Endpoint", "DomainProcessingStatus")}
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
