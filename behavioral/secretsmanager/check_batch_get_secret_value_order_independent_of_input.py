"""batch-get-secret-value-order-independent-of-input."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-secret-value-order-independent-of-input"
GROUP = "ordering"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetSecretValue returns the correct value for every requested secret regardless
    of the order those identifiers appear in SecretIdList -- the response is a set keyed by
    identifier, not a positional echo of the request order."""
    sm = ctx.client("secretsmanager")
    secrets: dict[str, dict[str, str]] = {}
    for i in range(3):
        name = ctx.unique_name(f"sim2real-batchget-{i}-")
        created = sm.create_secret(
            Name=name,
            SecretString=f"value-{i}",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        arn = created["ARN"]
        ctx.on_cleanup(lambda a=arn: sm.delete_secret(SecretId=a, ForceDeleteWithoutRecovery=True))
        secrets[name] = {"arn": arn, "value": f"value-{i}"}

    names = list(secrets.keys())
    forward = sm.batch_get_secret_value(SecretIdList=names)
    backward = sm.batch_get_secret_value(SecretIdList=list(reversed(names)))

    expected = {name: info["value"] for name, info in secrets.items()}
    for resp in (forward, backward):
        assert resp.get("Errors", []) == [], f"unexpected per-item errors: {resp.get('Errors')}"
        by_name = {sv["Name"]: sv["SecretString"] for sv in resp["SecretValues"]}
        assert by_name == expected, (
            f"BatchGetSecretValue result depended on request order: {by_name} != {expected}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
