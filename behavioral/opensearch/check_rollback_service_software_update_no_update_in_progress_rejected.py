"""rollback-service-software-update-no-update-in-progress-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-service-software-update-no-update-in-progress-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackServiceSoftwareUpdate on an Active domain with no update in progress fails with
    ValidationException and its exact message or answers RollbackAvailable False, leaves UpdateStatus
    unchanged, and DescribeDomain still resolves the domain.
    """
    os_client = ctx.client("opensearch")

    domain_name = _short_name(ctx, "sim2real-rollbk-")
    os_client.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: os_client.delete_domain(DomainName=domain_name))
    before = _wait_domain_active(ctx, os_client, domain_name)
    before_software = before.get("ServiceSoftwareOptions", {})

    try:
        rollback_resp = os_client.rollback_service_software_update(DomainName=domain_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "ValidationException", (
            "expected ValidationException (or a 200 declining with RollbackAvailable=False) "
            f"when rolling back with no update in progress, got {code}"
        )
        assert message == (
            "A change/update is in progress. Please wait for it to complete before requesting "
            "another change."
        ), f"unexpected rollback refusal message: {message!r}"
    else:
        # Measured on real AWS: a 200 whose payload explicitly declines the rollback, rather
        # than an exception. RollbackAvailable=True here would mean AWS silently performed a
        # real rollback with nothing eligible to roll back to/from.
        rollback_opts = rollback_resp.get("RollbackServiceSoftwareOptions", {})
        assert rollback_opts.get("RollbackAvailable") is False, (
            "expected a 200 response to explicitly decline the rollback "
            f"(RollbackAvailable=False), got {rollback_opts}"
        )

    # Effect-absent: the rejected rollback must not have disturbed the domain's
    # service-software state.
    after_software = os_client.describe_domain(DomainName=domain_name)["DomainStatus"].get(
        "ServiceSoftwareOptions", {}
    )
    assert after_software.get("UpdateStatus") == before_software.get("UpdateStatus"), (
        "ServiceSoftwareOptions.UpdateStatus changed as a side effect of a rejected rollback: "
        f"{before_software.get('UpdateStatus')!r} -> {after_software.get('UpdateStatus')!r}"
    )

    described = os_client.describe_domain(DomainName=domain_name)
    assert described["DomainStatus"]["DomainName"] == domain_name, (
        f"expected the positive-control describe to name the same domain, got "
        f"{described['DomainStatus'].get('DomainName')!r}"
    )


def _short_name(ctx, prefix, max_len=28):
    name = ctx.unique_name(prefix)[:max_len]
    if not name[-1].isalnum():
        name = name[:-1] + "0"
    return name


def _wait_domain_active(ctx, client, domain_name, timeout_s=1800.0, interval_s=20.0):
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Created") and not last.get("Processing"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became active within {budget}s: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
