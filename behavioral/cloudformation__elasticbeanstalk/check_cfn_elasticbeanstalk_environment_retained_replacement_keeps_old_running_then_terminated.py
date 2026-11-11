"""cfn-elasticbeanstalk-environment-retained-replacement-keeps-old-running-then-terminated."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elasticbeanstalk-environment-retained-replacement-keeps-old-running-then-terminated"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticbeanstalk"]

#: An environment's launch, update or termination takes minutes; the cap only stops a hung poll.
_STACK_CAP_S = 1200.0
#: One deadline for the whole teardown, within the suites' 1800 s cleanup budget.
_TEARDOWN_CAP_S = 1700.0
_GONE_CAP_S = 300.0
#: A retained environment's termination in the body; teardown waits on the shared deadline.
_TERMINATE_CAP_S = 600.0
#: A Ready environment can take a few minutes to report its instance healthy.
_HEALTH_CAP_S = 600.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_INSTANCE_TYPE = "t3.micro"


def _not_found(app_name: str) -> tuple[str, str]:
    """Elastic Beanstalk's refusal of a template for an application that no longer exists."""
    return "InvalidParameterValue", f"No Application named '{app_name}' found."


def _template(app_name: str, env_name: str, description: str, solution_stack: str, net) -> str:
    """An Application and a SingleInstance Environment whose only security group admits nothing.

    The default EC2 group is disabled, so the public Elastic IP and CNAME reach nothing.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "InstanceSg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real eb instance, no ingress",
                        "VpcId": net.vpc_id,
                    },
                },
                "InstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            {
                                "Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/"
                                "AWSElasticBeanstalkWebTier"
                            }
                        ],
                    },
                },
                "InstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
                },
                "Application": {
                    "Type": "AWS::ElasticBeanstalk::Application",
                    "Properties": {"ApplicationName": app_name},
                },
                "Environment": {
                    "Type": "AWS::ElasticBeanstalk::Environment",
                    # EnvironmentName is create-only, so changing it replaces the environment.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ApplicationName": {"Ref": "Application"},
                        "EnvironmentName": env_name,
                        "Description": description,
                        "SolutionStackName": solution_stack,
                        "OptionSettings": [
                            {"Namespace": ns, "OptionName": name, "Value": value}
                            for ns, name, value in _options(net)
                        ],
                    },
                },
            },
            "Outputs": {
                "EnvironmentName": {"Value": {"Ref": "Environment"}},
                "EndpointURL": {"Value": {"Fn::GetAtt": ["Environment", "EndpointURL"]}},
                "InstanceSgId": {"Value": {"Ref": "InstanceSg"}},
                "InstanceProfileName": {"Value": {"Ref": "InstanceProfile"}},
            },
        }
    )


def _options(net):
    """``(namespace, option, value)`` of every OptionSetting the template sets."""
    lc = "aws:autoscaling:launchconfiguration"
    return [
        ("aws:elasticbeanstalk:environment", "EnvironmentType", "SingleInstance"),
        (lc, "IamInstanceProfile", {"Ref": "InstanceProfile"}),
        (lc, "InstanceType", _INSTANCE_TYPE),
        (lc, "DisableDefaultEC2SecurityGroup", "true"),
        (lc, "SecurityGroups", {"Ref": "InstanceSg"}),
        ("aws:ec2:vpc", "VPCId", net.vpc_id),
        ("aws:ec2:vpc", "Subnets", net.subnet_ids[0]),
        ("aws:ec2:vpc", "AssociatePublicIpAddress", "true"),
    ]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation Beanstalk environment survives replacement under UpdateReplacePolicy Retain.

    An EnvironmentName change makes a new environment with one healthy instance and keeps the old
    one running on its instance; once both terminate, the application is gone.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticbeanstalk-environment.html
    """
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    net = ctx.network()
    app_name = ctx.unique_name("sim2real-cfnebenv-app-")
    first = ctx.unique_name("s2r-ebe-a-")
    second = ctx.unique_name("s2r-ebe-b-")
    stack_name = ctx.unique_name("sim2real-cfnebenv-stack-")
    solution_stack = _solution_stack(eb)
    ref = {"stack": stack_name}
    env_ids: list[str] = []
    retained: dict = {}
    storage = f"elasticbeanstalk-{ctx.region}-{ctx.account}"

    # Elastic Beanstalk keeps one storage bucket per account and region, shared by every
    # environment; the check removes only the keys its own environments write.
    ctx.on_cleanup(lambda: _delete_environment_keys(s3, storage, eb, app_name, env_ids))
    # Every teardown wait shares one deadline (limit), which the body's deadline does not bound.
    limit: dict = {}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref, limit))
    # Runs before the stack's teardown (LIFO), while the application still lists its environments.
    ctx.on_cleanup(lambda: _collect_environment_ids(eb, app_name, env_ids))

    # ---- 1. create: CloudFormation's view, Elastic Beanstalk's view, one healthy instance
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(app_name, first, "first description", solution_stack, net),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = ref["stack"].split(":")[1]
    out = _outputs(stack)
    assert _physical_ids(cfn, ref["stack"])["Environment"] == first, (
        f"the environment's physical id must be its name {first!r}"
    )
    assert out["EnvironmentName"] == first, f"Ref output {out!r}"
    env = _assert_environment(
        ctx, eb, partition, app_name, first, "first description", solution_stack, out["EndpointURL"]
    )
    _assert_options(eb, app_name, first, net, out)
    instance = _assert_one_healthy_instance(ctx, eb, env["EnvironmentId"])

    # ---- 2. replacement under UpdateReplacePolicy Retain: a new environment, the old one kept
    # The retained environment outlives the stack resource and uses the stack's security group,
    # so its termination is registered before the update and runs before the stack's (LIFO).
    retained["id"] = env["EnvironmentId"]
    ctx.on_cleanup(lambda: _terminate_environment(None, eb, retained.get("id"), limit))
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(app_name, second, "first description", solution_stack, net),
        Tags=_TAGS,
        Capabilities=["CAPABILITY_IAM"],
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    new_out = _outputs(stack)
    assert _physical_ids(cfn, ref["stack"])["Environment"] == second, (
        f"the replacement's physical id must be its name {second!r}"
    )
    assert new_out["EnvironmentName"] == second, f"Ref output after replacement {new_out!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Environment"), first, second, "Environment"
    )
    replacement = _assert_environment(
        ctx,
        eb,
        partition,
        app_name,
        second,
        "first description",
        solution_stack,
        new_out["EndpointURL"],
    )
    assert replacement["EnvironmentId"] != env["EnvironmentId"], (
        f"the replacement must be a new environment, still {env['EnvironmentId']!r}"
    )
    _assert_options(eb, app_name, second, net, new_out)
    _assert_one_healthy_instance(ctx, eb, replacement["EnvironmentId"])
    old = _assert_environment(
        ctx,
        eb,
        partition,
        app_name,
        first,
        "first description",
        solution_stack,
        out["EndpointURL"],
    )
    assert old["EnvironmentId"] == env["EnvironmentId"], f"the retained environment reads {old!r}"
    assert _assert_one_healthy_instance(ctx, eb, env["EnvironmentId"]) == instance, (
        f"the retained environment must keep running its instance {instance!r}"
    )

    # ---- 3. delete: the retained environment is terminated first (it uses the stack's group)
    _terminate_environment(ctx, eb, env["EnvironmentId"])
    _delete_stack(ctx, cfn, ref["stack"])
    gone = _wait_status(ctx, eb, replacement["EnvironmentId"], "Terminated", _GONE_CAP_S)
    assert gone["EnvironmentName"] == second, f"tombstone {gone!r}"
    got = _error(
        lambda: eb.create_configuration_template(
            ApplicationName=app_name,
            TemplateName=ctx.unique_name("sim2real-cfnebenv-tmpl-"),
            SolutionStackName=solution_stack,
        )
    )
    assert got == _not_found(app_name), f"CreateConfigurationTemplate after delete: {got!r}"
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert apps == [], f"DescribeApplications still lists the deleted application: {apps!r}"


def _solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    python_stacks = [s for s in stacks if "running Python" in s]
    assert python_stacks, f"no Python solution stack in this account and region, got {stacks!r}"
    return python_stacks[0]


def _assert_environment(
    ctx, eb, partition, app_name, env_name, description, solution_stack, endpoint_url
) -> dict:
    """DescribeEnvironments reports the environment Ready, exactly as templated.

    Polled: an update reads Updating until Elastic Beanstalk has applied it.
    """
    arn = (
        f"arn:{partition}:elasticbeanstalk:{ctx.region}:{ctx.account}"
        f":environment/{app_name}/{env_name}"
    )
    want = (
        env_name,
        app_name,
        arn,
        "Ready",
        solution_stack,
        description,
        endpoint_url,
        {"Name": "WebServer", "Type": "Standard"},
    )
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        envs = eb.describe_environments(ApplicationName=app_name, EnvironmentNames=[env_name])[
            "Environments"
        ]
        got = [
            (
                e["EnvironmentName"],
                e["ApplicationName"],
                e.get("EnvironmentArn"),
                e["Status"],
                e.get("SolutionStackName"),
                e.get("Description"),
                e.get("EndpointURL"),
                {k: e.get("Tier", {}).get(k) for k in ("Name", "Type")},
            )
            for e in envs
        ]
        if got == [want]:
            return envs[0]
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {env_name} read {want!r}")
            raise AssertionError(f"DescribeEnvironments {got!r}, expected [{want!r}]")
        time.sleep(_POLL_S)


def _assert_options(eb, app_name: str, env_name: str, net, out: dict) -> None:
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, EnvironmentName=env_name
    )["ConfigurationSettings"]
    assert len(settings) == 1, f"describe_configuration_settings returned {settings!r}"
    options = {
        (o["Namespace"], o["OptionName"]): o.get("Value") for o in settings[0]["OptionSettings"]
    }
    refs = {"InstanceProfile": out["InstanceProfileName"], "InstanceSg": out["InstanceSgId"]}
    want = {
        (ns, name): refs[v["Ref"]] if isinstance(v, dict) else v for ns, name, v in _options(net)
    }
    got = {key: options.get(key) for key in want}
    assert got == want, f"option settings of {env_name} {got!r}, expected {want!r}"


def _assert_one_healthy_instance(ctx, eb, env_id: str) -> str:
    """The environment runs exactly one instance and reports Green health; its instance id.

    Polled: a just-Ready environment can read Grey until its first health check completes.
    """
    timeout = _budget_s(ctx, _HEALTH_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        resources = eb.describe_environment_resources(EnvironmentId=env_id)["EnvironmentResources"]
        instances = [i["Id"] for i in resources.get("Instances", [])]
        health = eb.describe_environments(EnvironmentIds=[env_id])["Environments"][0].get("Health")
        if len(instances) == 1 and health == "Green":
            return instances[0]
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {env_id} ran one Green instance")
            raise AssertionError(
                f"environment {env_id} must run exactly one instance with Green health, it has "
                f"instances {instances!r} and health {health!r}"
            )
        time.sleep(_POLL_S)


def _wait_status(ctx, eb, env_id: str, target: str, cap_s: float) -> dict:
    """DescribeEnvironments (deleted included) polled until the environment reads *target*."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        envs = eb.describe_environments(EnvironmentIds=[env_id], IncludeDeleted=True)[
            "Environments"
        ]
        assert len(envs) == 1, f"DescribeEnvironments({env_id!r}) returned {envs!r}"
        if envs[0]["Status"] == target:
            return envs[0]
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {env_id} was {envs[0]['Status']!r}")
            raise AssertionError(
                f"environment {env_id} still {envs[0]['Status']!r}, not {target!r}"
            )
        time.sleep(_POLL_S)


def _terminate_environment(ctx, eb, env_id: str | None, limit: dict | None = None) -> None:
    """Terminate the environment and wait for 'Terminated'; one already terminating is waited.

    In teardown (*limit* given) every wait shares the one teardown deadline.
    """
    if env_id is None:
        return
    envs = eb.describe_environments(EnvironmentIds=[env_id], IncludeDeleted=True)["Environments"]
    if not envs or envs[0]["Status"] == "Terminated":
        return

    def cap() -> float:
        return _TERMINATE_CAP_S if limit is None else _remaining(limit)

    if envs[0]["Status"] != "Terminating":
        if envs[0]["Status"] != "Ready":
            _wait_status(ctx, eb, env_id, "Ready", cap())
        eb.terminate_environment(EnvironmentId=env_id, TerminateResources=True)
    _wait_status(ctx, eb, env_id, "Terminated", cap())


def _collect_environment_ids(eb, app_name: str, env_ids: list[str]) -> None:
    """Add the id of every environment of *app_name*, terminated ones included, to *env_ids*."""
    envs = eb.describe_environments(ApplicationName=app_name, IncludeDeleted=True)["Environments"]
    env_ids.extend(e["EnvironmentId"] for e in envs if e["EnvironmentId"] not in env_ids)


def _delete_environment_keys(s3, bucket: str, eb, app_name: str, env_ids: list[str]) -> None:
    """Delete exactly the storage-bucket keys Elastic Beanstalk wrote for this run's environments.

    The bucket is an account-wide singleton other runs share, so only keys under the
    environments' own ids (their resources and their logs) are removed, never the bucket.
    """
    _collect_environment_ids(eb, app_name, env_ids)
    for env_id in env_ids:
        keys = []
        for prefix in (f"resources/environments/{env_id}/", "resources/environments/logs/"):
            try:
                pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
                listed = [o for page in pages for o in page.get("Contents", [])]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchBucket":
                    return
                raise
            keys += [o["Key"] for o in listed if env_id in o["Key"].split("/")]
        for start in range(0, len(keys), 1000):
            batch = [{"Key": k} for k in keys[start : start + 1000]]
            errors = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch}).get("Errors", [])
            assert not errors, f"failed to delete {errors!r} from {bucket!r}"


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. With ctx None (teardown) it is cap_s.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack(ctx, cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, cap_s), "DELETE_COMPLETE")


def _remaining(limit: dict) -> float:
    """Seconds left of the one teardown deadline, which starts at the first teardown wait."""
    deadline = limit.setdefault("at", time.monotonic() + _TEARDOWN_CAP_S)
    return max(1.0, deadline - time.monotonic())


def _teardown_stack(cfn, ref: dict, limit: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Every wait shares the one deadline in *limit*, so the whole teardown fits its cap.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"], _remaining(limit))
    _delete_stack(None, cfn, stack["StackId"], _remaining(limit))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
