"""domain-replication-and-configuration-comparison-reject-unknown-targets."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "domain-replication-and-configuration-comparison-reject-unknown-targets"
GROUP = "domain-introspection"
SERVICES = ["opensearch"]

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

_UNSUPPORTED_CATEGORIES_MESSAGE = (
    "Unsupported category: sim2real-bogus-category. Supported: [cluster_settings, "
    "security_role_mappings, ism_policies, security_internal_users, aliases, "
    "alerting_monitors, templates, component_templates, security_roles, "
    "security_action_groups, ingest_pipelines]"
)


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _retry_throttle(fn, *, attempts=8, base_delay_s=5.0):
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == attempts - 1:
                raise
            time.sleep(base_delay_s * (attempt + 1) + random.uniform(0, base_delay_s))
    raise AssertionError("unreachable")


def _create_domain(ctx, osc, name: str) -> None:
    kwargs = dict(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    _retry_throttle(lambda: osc.create_domain(**kwargs))
    ctx.on_cleanup(lambda: _delete_domain(osc, name))


def _delete_domain(osc, name: str) -> None:
    try:
        osc.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, osc, name: str, timeout_s: float = 1500.0) -> dict:
    """A real OpenSearch domain needs 10-20 min to go Active."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(5)
    raise AssertionError(f"domain {name} never became Active within {timeout_s}s; last={last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDomainReplication reports an unreplicated domain with empty Peers and no Role,
    and CompareDomainConfiguration reports a self-compare as fully in sync; both refuse an
    unknown domain, and CompareDomainConfiguration also refuses an unrecognized category."""
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    status = _wait_domain_active(ctx, osc, domain)
    domain_arn = status["ARN"]

    missing_domain = ctx.unique_name("sim2real-miss-")[:28].rstrip("-")
    missing_arn = f"arn:aws:es:{ctx.region}:{ctx.account}:domain/{missing_domain}"

    # --- DescribeDomainReplication: positive control, then the unknown-domain refusal ---
    replication = osc.describe_domain_replication(DomainName=domain)
    assert replication.get("Peers") == [], (
        f"a domain with no replication peers must report an empty Peers list, got {replication.get('Peers')!r}"
    )
    assert "Role" not in replication, (
        f"a domain with no replication arrangement must report no Role, got {replication.get('Role')!r}"
    )

    repl_code, repl_message = _error(
        lambda: osc.describe_domain_replication(DomainName=missing_domain)
    )
    assert repl_code == "ResourceNotFoundException", (
        f"DescribeDomainReplication on a domain name that does not exist: expected "
        f"ResourceNotFoundException, got {repl_code!r}: {repl_message!r}"
    )
    expected_repl_message = f"Domain not found: {missing_arn}"
    assert repl_message == expected_repl_message, (
        f"DescribeDomainReplication not-found message was {repl_message!r}, expected {expected_repl_message!r}"
    )

    # --- CompareDomainConfiguration: a domain compared against itself is fully in sync ---
    self_compare = osc.compare_domain_configuration(
        SourceDomainArn=domain_arn, TargetDomainArn=domain_arn, Categories=["cluster_settings"]
    )
    cluster_settings_diff = self_compare["Categories"]["cluster_settings"]
    assert cluster_settings_diff["Status"] == "compared", (
        f"a self-compare must report Status 'compared', got {cluster_settings_diff['Status']!r}"
    )
    assert cluster_settings_diff["Diverged"] == 0, (
        f"a domain compared against itself must have 0 diverged items, got {cluster_settings_diff['Diverged']!r}"
    )
    assert cluster_settings_diff["SourceOnly"] == 0, (
        f"a domain compared against itself must have 0 source-only items, got {cluster_settings_diff['SourceOnly']!r}"
    )
    assert cluster_settings_diff["TargetOnly"] == 0, (
        f"a domain compared against itself must have 0 target-only items, got {cluster_settings_diff['TargetOnly']!r}"
    )

    # --- CompareDomainConfiguration: break exactly the source domain ---
    source_code, source_message = _error(
        lambda: osc.compare_domain_configuration(
            SourceDomainArn=missing_arn, TargetDomainArn=domain_arn, Categories=["cluster_settings"]
        )
    )
    assert source_code == "ValidationException", (
        f"CompareDomainConfiguration with an unknown source domain: expected ValidationException, "
        f"got {source_code!r}: {source_message!r}"
    )
    expected_source_message = f"Source domain {missing_domain}: Domain {missing_domain} not found."
    assert source_message == expected_source_message, (
        f"unknown-source message was {source_message!r}, expected {expected_source_message!r}"
    )

    # --- CompareDomainConfiguration: break exactly the target domain ---
    target_code, target_message = _error(
        lambda: osc.compare_domain_configuration(
            SourceDomainArn=domain_arn, TargetDomainArn=missing_arn, Categories=["cluster_settings"]
        )
    )
    assert target_code == "ValidationException", (
        f"CompareDomainConfiguration with an unknown target domain: expected ValidationException, "
        f"got {target_code!r}: {target_message!r}"
    )
    expected_target_message = f"Target domain {missing_domain}: Domain {missing_domain} not found."
    assert target_message == expected_target_message, (
        f"unknown-target message was {target_message!r}, expected {expected_target_message!r}"
    )

    # --- CompareDomainConfiguration: break exactly the category, on the real domain pair ---
    category_code, category_message = _error(
        lambda: osc.compare_domain_configuration(
            SourceDomainArn=domain_arn,
            TargetDomainArn=domain_arn,
            Categories=["sim2real-bogus-category"],
        )
    )
    assert category_code == "ValidationException", (
        f"CompareDomainConfiguration with an unrecognized category: expected ValidationException, "
        f"got {category_code!r}: {category_message!r}"
    )
    assert category_message == _UNSUPPORTED_CATEGORIES_MESSAGE, (
        f"unsupported-category message was {category_message!r}, expected {_UNSUPPORTED_CATEGORIES_MESSAGE!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
