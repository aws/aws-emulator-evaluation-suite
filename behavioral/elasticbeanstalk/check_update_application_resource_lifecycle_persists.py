"""update-application-resource-lifecycle-persists."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-application-resource-lifecycle-persists"
GROUP = 'application-versions'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS rejects a lifecycle config without ServiceRole, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _retry_while_role_not_ready(fn, *, timeout_s=90, interval_s=5.0):
    """IAM is eventually consistent; EB may reject a ServiceRole it cannot yet see with
    InvalidParameterValue. Retry that specific rejection, bounded, until it clears or the
    deadline passes — then let whatever error is current propagate."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValue":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _ensure_env_iam(ctx):
    """Best-effort: create the instance profile + service role an EB environment needs,
    registering LIFO teardown. Returns (instance_profile|None, service_role|None); degrades
    to (None, None) when IAM is unreachable (an emulator that does not serve IAM), letting the
    service apply its defaults. Memoized on ctx so an env-creating check provisions IAM once."""
    if hasattr(ctx, "_eb_iam"):
        return ctx._eb_iam
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        ctx._eb_iam = (None, None)
        return ctx._eb_iam

    def _create_role(name, service, policy_arns):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}
            ],
        }
        try:
            iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except Exception as exc:  # noqa: BLE001 — already-exists is fine
            if "EntityAlreadyExists" not in str(exc):
                return False
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policy_arns:
            try:
                iam.attach_role_policy(RoleName=name, PolicyArn=arn)
                ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))
            except Exception:  # noqa: BLE001
                pass
        return True

    ec2_role = ctx.unique_name("sim2real-behav-eb-ec2-role-")
    svc_role = ctx.unique_name("sim2real-behav-eb-service-role-")
    profile = ctx.unique_name("sim2real-behav-eb-ec2-profile-")
    ec2_ok = _create_role(
        ec2_role, "ec2.amazonaws.com", ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"]
    )
    service_role = (
        svc_role
        if _create_role(
            svc_role,
            "elasticbeanstalk.amazonaws.com",
            [
                "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
                "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
            ],
        )
        else None
    )
    instance_profile = None
    if ec2_ok:
        made = True
        try:
            iam.create_instance_profile(
                InstanceProfileName=profile,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
        except Exception as exc:  # noqa: BLE001
            if "EntityAlreadyExists" not in str(exc):
                made = False
        if made:
            try:
                iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
                ctx.on_cleanup(
                    lambda: iam.remove_role_from_instance_profile(
                        InstanceProfileName=profile, RoleName=ec2_role
                    )
                )
            except Exception:  # noqa: BLE001
                pass
            instance_profile = profile
    ctx._eb_iam = (instance_profile, service_role)
    return ctx._eb_iam


def _service_role_arn(ctx):
    """ARN of a harness-managed Elastic Beanstalk service role (provisions IAM on demand)."""
    _, service_role = _ensure_env_iam(ctx)
    if not service_role:
        raise AssertionError("IAM is unavailable; cannot resolve an EB service role ARN")
    return ctx.client("iam").get_role(RoleName=service_role)["Role"]["Arn"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplicationResourceLifecycle requires a ServiceRole and then persists the config."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    lifecycle = {
        "VersionLifecycleConfig": {
            "MaxCountRule": {
                "Enabled": True,
                "MaxCount": 3,
                "DeleteSourceFromS3": False,
            },
            "MaxAgeRule": {"Enabled": False},
        }
    }

    # Without a ServiceRole the request is rejected outright.
    code, message = _err(
        lambda: eb.update_application_resource_lifecycle(
            ApplicationName=app_name, ResourceLifecycleConfig=lifecycle
        )
    )
    assert code == "InvalidParameterValue", (
        f"a lifecycle config without ServiceRole must be rejected with InvalidParameterValue, "
        f"got {code!r}"
    )
    expected_message = "Parameter ServiceRole is invalid. Must be a valid IAM Role ARN."
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    role_arn = _service_role_arn(ctx)
    resp = _retry_while_role_not_ready(
        lambda: eb.update_application_resource_lifecycle(
            ApplicationName=app_name,
            ResourceLifecycleConfig={**lifecycle, "ServiceRole": role_arn},
        )
    )
    assert resp["ApplicationName"] == app_name, (
        f"expected the update response to name {app_name!r}, got {resp.get('ApplicationName')!r}"
    )
    rule = resp["ResourceLifecycleConfig"]["VersionLifecycleConfig"]["MaxCountRule"]
    assert rule["Enabled"] is True, f"expected MaxCountRule.Enabled True in the update response, got {rule.get('Enabled')!r}"
    assert rule["MaxCount"] == 3, f"expected MaxCountRule.MaxCount 3 in the update response, got {rule.get('MaxCount')!r}"

    described = eb.describe_applications(ApplicationNames=[app_name])["Applications"][0]
    stored = described["ResourceLifecycleConfig"]["VersionLifecycleConfig"]["MaxCountRule"]
    assert stored["Enabled"] is True, "lifecycle config must persist on the application record"
    assert stored["MaxCount"] == 3, f"expected the persisted MaxCountRule.MaxCount to stay 3, got {stored.get('MaxCount')!r}"
    assert described["ResourceLifecycleConfig"]["ServiceRole"] == role_arn, (
        f"expected the persisted ServiceRole to remain {role_arn!r}, got "
        f"{described['ResourceLifecycleConfig'].get('ServiceRole')!r}"
    )
    max_age_enabled = described["ResourceLifecycleConfig"]["VersionLifecycleConfig"]["MaxAgeRule"]["Enabled"]
    assert max_age_enabled is False, (
        f"expected the disabled MaxAgeRule to persist as Enabled=False, got {max_age_enabled!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
