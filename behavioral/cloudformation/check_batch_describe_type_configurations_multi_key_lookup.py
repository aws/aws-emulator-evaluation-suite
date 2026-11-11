"""batch-describe-type-configurations-multi-key-lookup."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "batch-describe-type-configurations-multi-key-lookup"
GROUP = "data-plane"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDescribeTypeConfigurations resolves two activated extensions' configurations in one
    call, each entry carrying the type ARN and alias of the identifier that asked for it."""
    cfn = ctx.client("cloudformation")
    role_arn = _execution_role(ctx)
    wanted = {_activate(ctx, role_arn): "AliasA", _activate(ctx, role_arn): "AliasB"}
    for type_arn, alias in wanted.items():
        cfn.set_type_configuration(
            TypeArn=type_arn, ConfigurationAlias=alias, Configuration=json.dumps({})
        )

    resp = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[
            {"TypeArn": type_arn, "TypeConfigurationAlias": alias}
            for type_arn, alias in wanted.items()
        ]
    )
    assert resp["Errors"] == [], f"expected no per-item errors, got {resp['Errors']}"
    assert resp["UnprocessedTypeConfigurations"] == [], (
        f"expected both identifiers processed, got {resp['UnprocessedTypeConfigurations']}"
    )
    assert len(resp["TypeConfigurations"]) == 2, (
        f"expected one entry per identifier, got {resp['TypeConfigurations']}"
    )
    got = {c["TypeArn"]: c for c in resp["TypeConfigurations"]}
    assert set(got) == set(wanted), f"expected entries for {sorted(wanted)}, got {sorted(got)}"
    for type_arn, alias in wanted.items():
        entry = got[type_arn]
        assert entry["Alias"] == alias, f"{type_arn}: expected alias {alias}, got {entry['Alias']}"
        assert json.loads(entry["Configuration"]) == {}, (
            f"{type_arn}: expected the empty configuration set on it, got {entry['Configuration']}"
        )
        assert entry["Arn"].endswith(f"/{alias}"), (
            f"{type_arn}: expected a type-configuration ARN ending in /{alias}, got {entry['Arn']}"
        )


#: A public third-party resource type whose ConfigurationSchema requires no property, so the
#: empty configuration is valid and nothing names a credential; activation invokes no handler.
PUBLIC_TYPE = "7171b96e5d207b947eb72ca9ce05247c246de623/Datadog-Monitors-Monitor"
MAJOR_VERSION = 4


def _execution_role(ctx) -> str:
    """A trust-only role CloudFormation assumes as the extension's ExecutionRoleArn; the type's
    handlers list no permissions, and activation never runs one."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfntype-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _activate(ctx, role_arn: str) -> str:
    """Activate the public type under a run-unique alias and return its ARN; the alias is this
    run's own, so its deactivation at cleanup never touches another activation."""
    cfn = ctx.client("cloudformation")
    alias = "Sim2Real::" + ctx.unique_name("Ext").replace("-", "") + "::Monitor"
    public_arn = f"arn:aws:cloudformation:{ctx.region}::type/resource/{PUBLIC_TYPE}"
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:
        try:
            type_arn = cfn.activate_type(
                PublicTypeArn=public_arn,
                TypeNameAlias=alias,
                ExecutionRoleArn=role_arn,
                MajorVersion=MAJOR_VERSION,
                AutoUpdate=False,
            )["Arn"]
            break
        except cfn.exceptions.CFNRegistryException as exc:
            # A just-created role's trust policy can take seconds to be assumable; any other
            # refusal is final.
            if "role" not in exc.response["Error"]["Message"].lower():
                raise
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("ActivateType: the run budget ran out; not graded") from exc
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cfn.deactivate_type(Arn=type_arn))
    return type_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
