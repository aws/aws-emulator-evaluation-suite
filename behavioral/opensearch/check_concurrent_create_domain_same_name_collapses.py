"""concurrent-create-domain-same-name-collapses."""
from __future__ import annotations

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-domain-same-name-collapses"
GROUP = 'domain'
SERVICES = ['opensearch']

MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
}

MIN_EBS_OPTIONS = {
    "EBSEnabled": True,
    "VolumeType": "gp3",
    "VolumeSize": 10,
}

ENGINE_VERSION = "OpenSearch_2.11"

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateDomain calls with one DomainName collapse onto exactly one domain; repeat creates
    are idempotent, and losers fail only with already-exists, throttling or validation codes.
    """
    os = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-race-")[:28].rstrip("-")
    # Best-effort teardown so we never leave a 24x7 cluster running.
    ctx.on_cleanup(lambda: os.delete_domain(DomainName=domain_name))

    def create():
        return os.create_domain(
            DomainName=domain_name,
            EngineVersion=ENGINE_VERSION,
            ClusterConfig=dict(MIN_CLUSTER_CONFIG),
            EBSOptions=dict(MIN_EBS_OPTIONS),
            TagList=[{"Key": "sim2real", "Value": CHECK}],
        )

    fns = [create for _ in range(4)]
    results = [None] * len(fns)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futs = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for assertion
                results[i] = exc

    n_success = sum(1 for r in results if not isinstance(r, BaseException))
    error_codes = []
    for r in results:
        if isinstance(r, ClientError):
            error_codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            error_codes.append(type(r).__name__)

    allowed = {"ResourceAlreadyExistsException", "ThrottlingException", "ValidationException"}
    assert all(c in allowed for c in error_codes), (
        f"losers must fail with {sorted(allowed)}, got {error_codes}"
    )
    # Exact texts AWS returns for the two refusals that carry a fixed message.
    expected_messages = {
        "ThrottlingException": "Rate exceeded",
        "ValidationException": (
            "A change/update is in progress. Please wait for it to complete before requesting another change."
        ),
    }
    for r in results:
        if isinstance(r, ClientError) and r.response["Error"]["Code"] in expected_messages:
            message = r.response["Error"]["Message"]
            assert message == expected_messages[r.response["Error"]["Code"]], (
                f"CreateDomain {r.response['Error']['Code']} message {message!r}"
            )

    assert n_success >= 1, f"no racer's CreateDomain was accepted; refusals: {error_codes}"

    # Every accepted create must have collapsed onto a single resource.
    listed = [
        d
        for d in os.list_domain_names()["DomainNames"]
        if d["DomainName"] == domain_name
    ]
    expected_count = 1
    assert len(listed) == expected_count, (
        f"{n_success} accepted create(s) must collapse to {expected_count} domain(s), "
        f"found {len(listed)} named {domain_name}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
