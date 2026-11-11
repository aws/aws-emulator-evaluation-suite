"""environment-info-tail-log-content-round-trip."""
from __future__ import annotations

import json
import time
import urllib.request
from typing import Any, Callable

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "environment-info-tail-log-content-round-trip"
GROUP = "representation"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """RetrieveEnvironmentInfo(InfoType="tail") returns a presigned URL whose downloaded tail log
    round-trips byte-for-byte across two reads of the same compilation, even though each call re-signs
    a different URL.
    """
    # Provisioning a real EB environment (EC2 + ASG) takes ~5-10 minutes and bills
    # real infrastructure. It is provisioned on every backend, real AWS included, as
    # a SingleInstance environment (one instance, no load balancer) and terminated in
    # cleanup.
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    solution_stack = _pick_solution_stack(eb)
    ec2_profile_name = _create_or_adopt_ec2_instance_profile(ctx)

    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=solution_stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {
                "Namespace": "aws:elasticbeanstalk:environment",
                "OptionName": "EnvironmentType",
                "Value": "SingleInstance",
            },
            {
                "Namespace": "aws:autoscaling:launchconfiguration",
                "OptionName": "IamInstanceProfile",
                "Value": ec2_profile_name,
            },
        ],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))

    _wait_env_ready(ctx, eb, app_name, env_name, timeout_s=900)

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")

    info_list = _poll_until(
        lambda: eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail").get(
            "EnvironmentInfo", []
        ),
        lambda info: len(info) > 0,
        timeout_s=180,
        interval_s=10,
    )
    assert len(info_list) > 0, "RetrieveEnvironmentInfo never produced any tail-log entries"

    first_entry = info_list[0]
    url_1 = first_entry["Message"]
    assert not (p := ctx.published_url_mismatch(url_1)), p
    content_1 = _download(ctx, url_1)
    assert len(content_1) > 0, "downloaded tail-log artifact was empty"

    # A second Retrieve call without an intervening Request must return a fetch URL
    # for the exact same compiled content -- it retrieves a cached compilation, it
    # doesn't recompile on every read. The URL itself differs each call (it is
    # freshly presigned), so the round trip is proven on the downloaded bytes.
    info_list_2 = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")[
        "EnvironmentInfo"
    ]
    matching = [e for e in info_list_2 if e.get("Ec2InstanceId") == first_entry.get("Ec2InstanceId")]
    assert matching, "second RetrieveEnvironmentInfo lost the instance's tail-log entry"
    url_2 = matching[0]["Message"]
    content_2 = _download(ctx, url_2)

    assert content_1 == content_2, "tail-log content changed between two reads of the same compilation"
    # The tail log is multi-line application-server output; a faithful transport
    # must preserve literal newline bytes, not escape or collapse them.
    assert b"\n" in content_1, f"tail-log artifact lost its newline structure: {content_1[:300]!r}"


def _download(ctx, url: str) -> bytes:
    with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
        return resp.read()


def _create_or_adopt_ec2_instance_profile(ctx) -> str:
    """Fresh sandbox accounts have no default EB EC2 instance profile; create one and
    tag it for cleanup discovery. create_environment rejects an environment with no
    instance profile associated with it (confirmed on real AWS)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eb-ec2-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))

    iam.create_instance_profile(InstanceProfileName=name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name))
    return name


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    assert stacks, "account has no available solution stacks"
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    return stacks[0]


def _wait_env_ready(ctx, eb, app_name: str, env_name: str, timeout_s: float) -> None:
    def probe() -> str:
        envs = eb.describe_environments(ApplicationName=app_name, EnvironmentNames=[env_name])[
            "Environments"
        ]
        return envs[0]["Status"] if envs else "Unknown"

    status = _poll_until(probe, lambda s: s in ("Ready", "Terminated"), timeout_s=timeout_s, interval_s=20)
    if status != "Ready":
        events = eb.describe_events(ApplicationName=app_name, EnvironmentName=env_name, MaxRecords=20)["Events"]
        detail = "; ".join(f"{e['Severity']}:{e['Message']}" for e in events)
        raise AssertionError(f"environment did not reach Ready (status={status}); events: {detail}")


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
