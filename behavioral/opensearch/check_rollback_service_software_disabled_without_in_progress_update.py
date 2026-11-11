"""rollback-service-software-disabled-without-in-progress-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rollback-service-software-disabled-without-in-progress-update"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackServiceSoftwareUpdate on a domain with no update in progress fails with ValidationException
    and its exact message or answers RollbackAvailable False with its exact Description; for an unknown
    domain it fails with ResourceNotFoundException "Domain not found: <name>".
    """
    client = ctx.client("opensearch")
    domain = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, client, domain)

    try:
        rollback_resp = client.rollback_service_software_update(DomainName=domain)
    except ClientError as exc:
        # Real AWS refuses while the domain still runs post-create work behind Processing=False.
        code_no_update = exc.response["Error"]["Code"]
        message_no_update = exc.response["Error"].get("Message")
        assert code_no_update == "ValidationException", (
            f"expected ValidationException (or a 200 declining with RollbackAvailable=False), got {code_no_update!r}"
        )
        assert message_no_update == (
            "A change/update is in progress. Please wait for it to complete before requesting "
            "another change."
        ), f"unexpected rollback refusal message: {message_no_update!r}"
    else:
        # On a settled domain real AWS answers 200 and declines the rollback in the payload.
        rollback_opts = rollback_resp.get("RollbackServiceSoftwareOptions", {})
        assert rollback_opts.get("RollbackAvailable") is False, (
            f"expected the 200 to decline the rollback with RollbackAvailable=False, got {rollback_opts!r}"
        )
        assert rollback_opts.get("Description") == (
            "No previous software version available for rollback. Please contact AWS Support for "
            "assistance."
        ), f"unexpected rollback decline description: {rollback_opts.get('Description')!r}"

    # Contrast (not a hollow branch: this is a SECOND, independent assertion pinned to a
    # different precondition): the exact same operation against a domain that truly doesn't
    # exist must raise ResourceNotFoundException, not the same ValidationException --
    # proving the rejection above is about update-eligibility, not a blanket "always reject".
    missing_name = _domain_name(ctx, prefix="sim2real-missing-")
    code_missing, message_missing = _error(
        lambda: client.rollback_service_software_update(DomainName=missing_name)
    )
    assert code_missing == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent domain, got {code_missing}"
    )
    assert message_missing == f"Domain not found: {missing_name}", (
        f"unexpected not-found message: {message_missing!r}"
    )

    # Effect-absent: the domain's service-software state was not disturbed by the rejected call.
    options = client.describe_domain(DomainName=domain)["DomainStatus"]["ServiceSoftwareOptions"]
    assert options["UpdateStatus"] != "IN_PROGRESS", (
        f"rejected rollback call must not have started a real update, got UpdateStatus={options['UpdateStatus']!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _domain_name(ctx, prefix="sim2real-os-") -> str:
    raw = ctx.unique_name(prefix)
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if not name or not name[0].isalpha():
        name = "d" + name
    name = name[:28].rstrip("-")
    return name or "sim2realosdomain"


def _create_minimal_domain(ctx) -> str:
    client = ctx.client("opensearch")
    name = _domain_name(ctx)
    account = _account_id(ctx)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "es:*",
                "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/{name}/*",
            }
        ],
    }
    client.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
        TagList=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return name


def _wait_domain_active(ctx, client, name, timeout_s=1800.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Created") and not last.get("Processing", True):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} never became active within {timeout_s}s: {last}")


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
