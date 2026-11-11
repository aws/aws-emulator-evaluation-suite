"""describe-domain-auto-tunes-missing-domain-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-domain-auto-tunes-missing-domain-not-found"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDomainAutoTunes on a nonexistent domain raises ResourceNotFoundException with AWS's
    message, while the same call on a real, active domain succeeds (positive control).
    """
    client = ctx.client("opensearch")
    domain = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, client, domain)

    # Positive control: the same operation succeeds against a domain that really exists.
    ok = client.describe_domain_auto_tunes(DomainName=domain)
    assert "AutoTunes" in ok, f"expected an AutoTunes field for a live domain, got {ok}"

    missing_name = _domain_name(ctx, prefix="sim2real-missing-")
    code, message = _error(lambda: client.describe_domain_auto_tunes(DomainName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Domain not found: {missing_name}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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
        TagList=[{"Key": "sim2real-check", "Value": "describe-domain-auto-tunes-missing-domain-not-found"}],
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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises, because
    accepting input AWS refuses is the divergence this check catches."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
