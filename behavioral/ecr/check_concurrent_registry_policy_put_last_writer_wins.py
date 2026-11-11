"""concurrent-registry-policy-put-last-writer-wins."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-registry-policy-put-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """Two concurrent PutRegistryPolicy calls with differing documents resolve
    deterministically to exactly one of the two documents on GetRegistryPolicy -- no
    corruption, truncation, or partial merge of the two policies."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original = None
    try:
        original = ecr.get_registry_policy()["policyText"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
            raise

    def _restore():
        if original is None:
            try:
                ecr.delete_registry_policy()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                    raise
        else:
            ecr.put_registry_policy(policyText=original)

    ctx.on_cleanup(_restore)

    region = ctx.region

    def _policy_doc(sid: str, action: str) -> str:
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [action],
                "Resource": [f"arn:aws:ecr:{region}:{account_id}:repository/*"],
            }],
        })


    policy_a = _policy_doc("Sim2RealVariantA", "ecr:ReplicateImage")
    policy_b = _policy_doc("Sim2RealVariantB", "ecr:CreateRepository")

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(ecr.put_registry_policy, policyText=policy_a)
        fut_b = pool.submit(ecr.put_registry_policy, policyText=policy_b)
        fut_a.result()
        fut_b.result()

    final_text = ecr.get_registry_policy()["policyText"]
    final_parsed = json.loads(final_text)
    normalized_final = _normalize_policy(final_parsed)
    assert normalized_final in (_normalize_policy(json.loads(policy_a)), _normalize_policy(json.loads(policy_b))), (
        "registry policy after concurrent writes is neither submitted document -- "
        "possible corruption/partial merge"
    )
    winning_sid = final_parsed["Statement"][0]["Sid"]
    assert winning_sid in ("Sim2RealVariantA", "Sim2RealVariantB"), (
        f"winning statement Sid was {winning_sid!r}, expected one of "
        "Sim2RealVariantA/Sim2RealVariantB"
    )

    # a subsequent read is stable and keeps returning the same winner (no flapping)
    final_text_again = ecr.get_registry_policy()["policyText"]
    normalized_again = _normalize_policy(json.loads(final_text_again))
    assert normalized_again == normalized_final, (
        f"registry policy flapped between reads -- first read {normalized_final}, "
        f"second read {normalized_again}"
    )


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _normalize_policy(policy: dict) -> dict:
    """IAM/ECR may collapse single-element Action/Resource lists to bare strings on
    round-trip; normalize both sides to lists so semantic equality holds."""
    normalized_statements = []
    for stmt in policy["Statement"]:
        normalized_statements.append({
            "Sid": stmt.get("Sid"),
            "Effect": stmt["Effect"],
            "Principal": stmt["Principal"],
            "Action": sorted(_as_list(stmt["Action"])),
            "Resource": sorted(_as_list(stmt["Resource"])),
        })
    return {"Version": policy["Version"], "Statement": normalized_statements}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

