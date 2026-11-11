"""concurrent-put-resource-policy-no-corruption."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-resource-policy-no-corruption"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutResourcePolicy calls with two distinct policy documents settle on
    exactly one of the two documents (last-write-wins) -- never a merged/corrupted
    result containing statements or conditions from both."""
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-polrace-")
    secret = sm.create_secret(Name=secret_name, SecretString="policy-race")
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def _policy(sid: str, tag_value: str) -> str:
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
                "Condition": {"StringEquals": {"aws:PrincipalTag/race": tag_value}},
            }],
        })

    policy_a = _policy("PolicyA", "alpha")
    policy_b = _policy("PolicyB", "beta")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(sm.put_resource_policy, SecretId=secret_arn, ResourcePolicy=policy_a),
            pool.submit(sm.put_resource_policy, SecretId=secret_arn, ResourcePolicy=policy_b),
        ]
        for f in futures:
            f.result()  # both concurrent PutResourcePolicy calls must succeed cleanly

    final = json.loads(sm.get_resource_policy(SecretId=secret_arn)["ResourcePolicy"])
    statements = final["Statement"]
    assert len(statements) == 1, f"expected exactly one statement, got a merged/corrupted result: {statements}"
    sid = statements[0]["Sid"]
    assert sid in ("PolicyA", "PolicyB"), f"unexpected Sid {sid!r}"
    winning_source = policy_a if sid == "PolicyA" else policy_b
    winning_statement = json.loads(winning_source)["Statement"][0]
    assert statements[0]["Condition"] == winning_statement["Condition"], (
        f"winning statement {sid} lost/altered its Condition: "
        f"expected {winning_statement['Condition']}, got {statements[0]['Condition']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
