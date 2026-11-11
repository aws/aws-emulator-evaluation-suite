"""deploy-application-cfn-then-swap-cnames-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-application-cfn-then-swap-cnames-behaves"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SwapEnvironmentCNAMEs on two environments created by one CloudFormation stack really swaps
    their CNAMEs, verified via DescribeEnvironments rather than stack CREATE_COMPLETE."""
    eb = ctx.client("elasticbeanstalk")
    cfn = ctx.client("cloudformation")

    stack_platform = _pick_solution_stack(eb)
    profile, service_role = _eb_iam(ctx)

    def env_resource(app_name: str, name: str) -> dict:
        option_settings = [
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        ]
        if profile:
            option_settings.append(
                {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": profile}
            )
        if service_role:
            option_settings.append(
                {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role}
            )
        return {
            "Type": "AWS::ElasticBeanstalk::Environment",
            "DependsOn": "App",
            "Properties": {
                "ApplicationName": app_name,
                "EnvironmentName": name,
                "SolutionStackName": stack_platform,
                "OptionSettings": option_settings,
            },
        }

    # A stack refused only because the fresh roles have not yet propagated is replaced by a new one.
    deadline = _deadline(ctx, _IAM_PROPAGATION_S)
    while True:
        app_name = ctx.unique_name("sim2real-cfnswap-app-")
        env_a = ctx.unique_name("sim2real-cfns-a-")
        env_b = ctx.unique_name("sim2real-cfns-b-")
        stack_name = ctx.unique_name("sim2real-cfnswap-stack-")
        template = {
            "Resources": {
                "App": {
                    "Type": "AWS::ElasticBeanstalk::Application",
                    "Properties": {"ApplicationName": app_name},
                },
                "EnvA": env_resource(app_name, env_a),
                "EnvB": env_resource(app_name, env_b),
            }
        }
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda stack_name=stack_name: _delete_stack_and_wait(cfn, stack_name))
        try:
            _wait_for_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=1500)
            break
        except AssertionError as exc:
            if time.monotonic() >= deadline or not _iam_not_yet_usable(str(exc)):
                raise
        time.sleep(2)

    before_a = _wait_for_env_status(eb, env_a, {"Ready"}, timeout_s=120)
    before_b = _wait_for_env_status(eb, env_b, {"Ready"}, timeout_s=120)
    cname_a, cname_b = before_a["CNAME"], before_b["CNAME"]
    assert cname_a != cname_b, f"expected distinct CNAMEs before swap, got {cname_a!r} for both envs"

    eb.swap_environment_cnames(SourceEnvironmentName=env_a, DestinationEnvironmentName=env_b)

    after_a, after_b = _wait_for_cname_swap(eb, env_a, env_b, cname_a, cname_b, timeout_s=180)
    assert after_a["EnvironmentId"] == before_a["EnvironmentId"], (
        f"expected {env_a} to keep EnvironmentId {before_a['EnvironmentId']!r}, "
        f"got {after_a['EnvironmentId']!r}"
    )
    assert after_b["EnvironmentId"] == before_b["EnvironmentId"], (
        f"expected {env_b} to keep EnvironmentId {before_b['EnvironmentId']!r}, "
        f"got {after_b['EnvironmentId']!r}"
    )
    assert after_a["CNAME"] == cname_b, f"expected {env_a} to answer at {cname_b!r}, got {after_a['CNAME']!r}"
    assert after_b["CNAME"] == cname_a, f"expected {env_b} to answer at {cname_a!r}, got {after_b['CNAME']!r}"


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _eb_iam(ctx):
    """Create the instance profile + service role the environments need, with LIFO teardown; a
    CloudFormation-created environment gets no console bootstrap roles. Returns
    (instance_profile|None, service_role|None); (None, None) when IAM is unreachable."""
    iam = ctx.client("iam")
    try:
        iam.list_roles(MaxItems=1)
    except Exception:  # noqa: BLE001 — no IAM at all: let EB apply its defaults
        return None, None

    def _role(name, service, policies):
        trust = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                        Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
        for arn in policies:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
            ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=name, PolicyArn=a))

    ec2_role = ctx.unique_name("sim2real-cfnswap-ec2-role-")
    svc_role = ctx.unique_name("sim2real-cfnswap-svc-role-")
    profile = ctx.unique_name("sim2real-cfnswap-profile-")
    _role(ec2_role, "ec2.amazonaws.com",
          ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"])
    _role(svc_role, "elasticbeanstalk.amazonaws.com",
          ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
           "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"])
    iam.create_instance_profile(InstanceProfileName=profile,
                                 Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile, RoleName=ec2_role))
    # IAM exposes no condition that reports a principal is usable by another service; run()
    # replaces a stack refused over their propagation.
    return profile, svc_role


#: Bound for fresh IAM roles and instance profiles to become usable by Elastic Beanstalk.
_IAM_PROPAGATION_S = 120.0


def _deadline(ctx, budget_s):
    """A monotonic deadline `budget_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (budget_s if left is None else min(budget_s, max(0.0, left - 5)))


def _iam_not_yet_usable(message: str) -> bool:
    """An Elastic Beanstalk refusal of a role or instance profile that IAM has not yet propagated."""
    low = message.lower()
    return ("insufficientprivileges" in low or "not have permission" in low
            or "cannot be assumed" in low or "unable to assume" in low
            or ("instance profile" in low and ("not exist" in low or "invalid" in low))
            or ("invalidparametervalue" in low and "role" in low))



def _stack_failure_reasons(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name).get("StackEvents", [])
    reasons = [
        f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]
    return "; ".join(reasons[:5]) or "(no FAILED resource events found)"


def _wait_for_stack_status(cfn, stack_name: str, statuses, timeout_s: float = 1500.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in statuses:
            return last
        if last.endswith("FAILED") or last == "ROLLBACK_COMPLETE":
            raise AssertionError(
                f"stack {stack_name} entered {last}, expected one of {statuses}: "
                f"{_stack_failure_reasons(cfn, stack_name)}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {statuses}; last={last}")


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name).get("Stacks", [])
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        last = stacks[0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(
                f"stack {stack_name} failed to delete: {_stack_failure_reasons(cfn, stack_name)}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached DELETE_COMPLETE; last={last}")


def _wait_for_env_status(eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses}; last={last}")


def _wait_for_cname_swap(eb, env_a: str, env_b: str, cname_a: str, cname_b: str, timeout_s: float = 180.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last_a = last_b = None
    while time.monotonic() < deadline:
        envs = {
            e["EnvironmentName"]: e
            for e in eb.describe_environments(
                EnvironmentNames=[env_a, env_b], IncludeDeleted=False
            ).get("Environments", [])
        }
        last_a, last_b = envs.get(env_a), envs.get(env_b)
        if last_a and last_b and last_a["CNAME"] == cname_b and last_b["CNAME"] == cname_a:
            return last_a, last_b
        time.sleep(interval_s)
    raise AssertionError(f"CNAMEs never swapped; last_a={last_a}, last_b={last_b}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
