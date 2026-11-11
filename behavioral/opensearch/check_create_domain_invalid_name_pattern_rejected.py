"""create-domain-invalid-name-pattern-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-domain-invalid-name-pattern-rejected"
GROUP = "deploy"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain rejects a DomainName that violates the required naming pattern
    (lowercase-start, alnum/hyphen only) with ValidationException and creates nothing,
    while a well-formed CreateDomain call in the same file is accepted."""
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    invalid_name = "Invalid_Domain_123"
    # Defensive: if an over-permissive target actually creates this, still clean it up.
    ctx.on_cleanup(lambda: _delete_domain_quiet(osc, invalid_name))

    refusal = _error(
        lambda: osc.create_domain(
            DomainName=invalid_name,
            EngineVersion="OpenSearch_2.11",
            ClusterConfig={
                "InstanceType": "t3.small.search",
                "InstanceCount": 1,
                "DedicatedMasterEnabled": False,
                "ZoneAwarenessEnabled": False,
            },
            EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        )
    )
    assert refusal == ("ValidationException", (
        f"1 validation error detected: Value '{invalid_name}' at 'domainName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [a-z][a-z0-9\\-]+"
    )), (
        f"expected ValidationException with AWS's exact message rejecting DomainName "
        f"{invalid_name!r}, got {refusal!r}"
    )

    # effect is absent: no domain with that name exists
    names = {d["DomainName"] for d in osc.list_domain_names()["DomainNames"]}
    assert invalid_name not in names, (
        f"rejected DomainName {invalid_name!r} unexpectedly appears in ListDomainNames: {sorted(names)!r}"
    )

    # positive control: a valid name is accepted and actually appears in ListDomainNames
    valid_name = ctx.unique_name("sim2real-val-")[:28].rstrip("-") or "sim2real-val-fallback"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "es:*",
                "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{valid_name}/*",
            }
        ],
    }
    osc.create_domain(
        DomainName=valid_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
    )
    ctx.on_cleanup(lambda: _delete_domain_quiet(osc, valid_name))

    names_after = {d["DomainName"] for d in osc.list_domain_names()["DomainNames"]}
    assert valid_name in names_after, (
        f"positive-control DomainName {valid_name!r} missing from ListDomainNames: {sorted(names_after)!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code is None:
            raise
        return code, exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected CreateDomain to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _error_code_from_exc(exc):
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _delete_domain_quiet(osc, domain_name):
    try:
        osc.delete_domain(DomainName=domain_name)
    except Exception as exc:  # noqa: BLE001
        # A name that fails the DomainName pattern can never name a domain, so its
        # ValidationException means there is nothing to delete.
        if _error_code_from_exc(exc) not in ("ResourceNotFoundException", "ValidationException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
