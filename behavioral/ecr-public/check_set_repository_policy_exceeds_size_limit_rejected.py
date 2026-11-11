"""set-repository-policy-exceeds-size-limit-rejected."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "set-repository-policy-exceeds-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]


def _ecrpub_client(ctx):
    """ecr-public is served only from us-east-1, so pin that region."""
    from botocore.config import Config

    return ctx.client("ecr-public", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"}))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy over the 10240-character maximum is rejected with InvalidParameterException,
    not truncated, and the previous policy stays; a within-limit policy is still accepted."""
    ecrp = _ecrpub_client(ctx)


    repo_name = ctx.unique_name("sim2real-policysize-")
    ecrp.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    baseline_policy = _policy_with_statements(1)
    ecrp.set_repository_policy(repositoryName=repo_name, policyText=baseline_policy)

    # Parameter validation is off so botocore's modeled length check does not reject it locally.
    oversized_policy = _policy_with_statements(400)
    assert len(oversized_policy) > 10240, (
        f"test fixture is not actually oversized: {len(oversized_policy)} chars"
    )

    raw_client = _client_without_param_validation(ctx, "ecr-public")
    err = _error(
        lambda: raw_client.set_repository_policy(
            repositoryName=repo_name, policyText=oversized_policy
        )
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Must have length less than or equal to 10240'")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    current_policy = ecrp.get_repository_policy(repositoryName=repo_name)["policyText"]
    assert _normalize_policy(current_policy) == _normalize_policy(baseline_policy), (
        "rejected oversized policy must not replace or truncate the existing policy: "
        f"current={current_policy!r} baseline={baseline_policy!r}"
    )

    smaller_policy = _policy_with_statements(2)
    ecrp.set_repository_policy(repositoryName=repo_name, policyText=smaller_policy)
    updated_policy = ecrp.get_repository_policy(repositoryName=repo_name)["policyText"]
    assert _normalize_policy(updated_policy) == _normalize_policy(smaller_policy), (
        "a within-limit policy set after the rejection must be accepted and persisted verbatim: "
        f"current={updated_policy!r} expected={smaller_policy!r}"
    )


def _normalize_policy(policy_text: str):
    """Collapse single-element lists to scalars, as the service does on round-trip."""
    doc = json.loads(policy_text)
    for stmt in doc.get("Statement", []):
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in stmt and isinstance(stmt[key], list) and len(stmt[key]) == 1:
                stmt[key] = stmt[key][0]
    return doc


def _policy_with_statements(count: int) -> str:
    statements = [
        {
            "Sid": f"AllowPull{i}",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["ecr-public:BatchCheckLayerAvailability"],
        }
        for i in range(count)
    ]
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _client_without_param_validation(ctx, service):
    """A client with botocore's client-side validation off, so the request reaches the server."""
    from botocore.config import Config

    return ctx.client(service, region="us-east-1", config=Config(parameter_validation=False))



def _error(fn) -> Any:
    """Return the botocore Error dict from fn(); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
