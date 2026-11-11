"""batch-describe-type-configurations-partial-failure-isolation."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "batch-describe-type-configurations-partial-failure-isolation"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A batch mixing a configured activated extension with a never-registered type name returns the
    first in TypeConfigurations and the second as a 404 "TypeConfiguration not found" in Errors
    instead of failing the whole call."""
    cfn = ctx.client("cloudformation")
    missing_type_name = "Sim2Real::" + ctx.unique_name("Bad").replace("-", "") + "::Behav"
    type_arn = _activate(ctx, _execution_role(ctx))
    cfn.set_type_configuration(
        TypeArn=type_arn, ConfigurationAlias="PartialGood", Configuration=json.dumps({})
    )

    missing = {"Type": "RESOURCE", "TypeName": missing_type_name}
    resp = cfn.batch_describe_type_configurations(
        TypeConfigurationIdentifiers=[
            {"TypeArn": type_arn, "TypeConfigurationAlias": "PartialGood"},
            missing,
        ]
    )
    good = resp["TypeConfigurations"]
    assert [(c["TypeArn"], c["Alias"]) for c in good] == [(type_arn, "PartialGood")], (
        f"expected exactly the configured alias resolved, got {good}"
    )
    assert json.loads(good[0]["Configuration"]) == {}, (
        f"expected the empty configuration set on it, got {good[0]['Configuration']}"
    )
    assert resp["UnprocessedTypeConfigurations"] == [], (
        f"expected no unprocessed identifiers, got {resp['UnprocessedTypeConfigurations']}"
    )
    errors = resp["Errors"]
    assert len(errors) == 1, f"expected exactly one error entry, got {errors}"
    assert errors[0]["ErrorCode"] == "404", f"expected ErrorCode '404', got {errors[0]}"
    assert errors[0]["ErrorMessage"] == NOT_FOUND, f"expected {NOT_FOUND!r}, got {errors[0]}"
    assert errors[0]["TypeConfigurationIdentifier"] == missing, (
        f"expected the error to echo {missing}, got {errors[0]['TypeConfigurationIdentifier']}"
    )


#: A public third-party resource type whose ConfigurationSchema requires no property, so the
#: empty configuration is valid and nothing names a credential; activation invokes no handler.
PUBLIC_TYPE = "7171b96e5d207b947eb72ca9ce05247c246de623/Datadog-Monitors-Monitor"
MAJOR_VERSION = 4
NOT_FOUND = "TypeConfiguration not found"


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
