"""obs-ecs-1-stop-finished-alarm-monitored-deployment-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-ecs-1-stop-finished-alarm-monitored-deployment-rejected"
GROUP = "deployment-alarms"
SERVICES = ["cloudwatch", "ecs"]

_TERMINAL = {"SUCCESSFUL", "STOPPED", "ROLLBACK_SUCCESSFUL", "ROLLBACK_FAILED"}


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-alarm-failure.html
@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """StopServiceDeployment(ROLLBACK) on a finished alarm-monitored deployment is a ConflictException
    and changes nothing; on a deployment still MONITORING it is accepted and reverts the service.
    """
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")

    cluster = ctx.unique_name("sim2real-xsvc-depstop-")
    ecs.create_cluster(clusterName=cluster, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _retry_cluster_delete(ecs, cluster))

    family = ctx.unique_name("sim2real-xsvc-depstop-td-")
    tds: list[str] = []
    ctx.on_cleanup(lambda: _delete_task_definitions(ecs, tds))
    for version in ("1", "2"):
        tds.append(ecs.register_task_definition(
            family=family, requiresCompatibilities=["EC2"], networkMode="bridge",
            containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                   "memory": 64, "essential": True,
                                   "environment": [{"name": "REVISION", "value": version}]}],
        )["taskDefinition"]["taskDefinitionArn"])
    td_v1, td_v2 = tds

    alarm = ctx.unique_name("sim2real-xsvc-depstop-")
    cw.put_metric_alarm(
        AlarmName=alarm, AlarmDescription=f"sim2real {CHECK}", Namespace="Sim2Real/DeploymentAlarm",
        MetricName=alarm, Statistic="Sum", Period=60, EvaluationPeriods=1, Threshold=0.0,
        ComparisonOperator="GreaterThanThreshold", TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    cw.set_alarm_state(AlarmName=alarm, StateValue="OK", StateReason="sim2real baseline")

    # desiredCount 0 on the EC2 launch type: the deployment state machine and its alarm monitor
    # run in full with no instances and no network to provision.
    svc = ctx.unique_name("sim2real-xsvc-depstop-svc-")
    ecs.create_service(
        cluster=cluster, serviceName=svc, taskDefinition=td_v1, desiredCount=0, launchType="EC2",
        tags=[{"key": "sim2real", "value": CHECK}],
        deploymentConfiguration={"alarms": {"alarmNames": [alarm], "enable": True, "rollback": True}})
    ctx.on_cleanup(lambda: _delete_service(ecs, cluster, svc))

    first = _poll_until(lambda: _deployments(ecs, cluster, svc),
                        lambda d: len(d) == 1 and d[0]["status"] in _TERMINAL,
                        timeout_s=600.0, interval_s=10.0,
                        description=f"initial deployment of {svc} finishing")[0]
    assert first["status"] == "SUCCESSFUL", f"initial deployment ended {first['status']!r}: {first.get('statusReason')!r}"
    assert (first.get("alarms") or {}).get("status") == "MONITORING_COMPLETE", (
        f"finished deployment alarm monitor is {first.get('alarms')!r}; expected MONITORING_COMPLETE")
    first_arn = first["serviceDeploymentArn"]

    # --- negative: stop(ROLLBACK) on the finished deployment ---
    got = _error(lambda: ecs.stop_service_deployment(serviceDeploymentArn=first_arn,
                                                     stopType="ROLLBACK"))
    want = ("ConflictException", f"ServiceDeployment is stopping or has already finished for arn: {first_arn}")
    assert got == want, (
        f"StopServiceDeployment(ROLLBACK) on a SUCCESSFUL deployment returned {got!r}; "
        f"expected {want!r}")
    after = _describe(ecs, [first_arn])[0]
    assert after["status"] == "SUCCESSFUL" and not after.get("rollback"), (
        f"rejected stop still changed the finished deployment: status {after['status']!r}, "
        f"rollback {after.get('rollback')!r}")
    assert _svc(ecs, cluster, svc)["taskDefinition"] == td_v1, "rejected stop changed the service"
    assert [d["serviceDeploymentArn"] for d in _deployments(ecs, cluster, svc)] == [first_arn], (
        "rejected stop created a deployment")

    # --- positive control: stop(ROLLBACK) while the alarm monitor is still MONITORING ---
    ecs.update_service(cluster=cluster, service=svc, taskDefinition=td_v2)
    second = _poll_until(
        lambda: [d for d in _deployments(ecs, cluster, svc) if d["serviceDeploymentArn"] != first_arn],
        lambda d: len(d) == 1 and d[0]["status"] == "IN_PROGRESS"
        and (d[0].get("alarms") or {}).get("status") == "MONITORING",
        timeout_s=180.0, interval_s=5.0,
        description=f"the v2 deployment of {svc} IN_PROGRESS with its alarm MONITORING")[0]
    second_arn = second["serviceDeploymentArn"]
    resp = ecs.stop_service_deployment(serviceDeploymentArn=second_arn, stopType="ROLLBACK")
    assert resp.get("serviceDeploymentArn") == second_arn, f"stop returned {resp!r}"

    done = _poll_until(lambda: _describe(ecs, [second_arn])[0],
                       lambda d: d["status"] in _TERMINAL, timeout_s=600.0, interval_s=10.0,
                       description="the stopped v2 deployment finishing its rollback")
    assert done["status"] == "ROLLBACK_SUCCESSFUL", (
        f"accepted rollback stop ended {done['status']!r} ({done.get('statusReason')!r}); "
        f"expected ROLLBACK_SUCCESSFUL")
    rb_rev = (done.get("rollback") or {}).get("serviceRevisionArn")
    assert rb_rev, f"rolled-back deployment carries no rollback revision: {done.get('rollback')!r}"
    rb_td = ecs.describe_service_revisions(serviceRevisionArns=[rb_rev])["serviceRevisions"][0]["taskDefinition"]
    assert rb_td == td_v1, f"rollback revision runs {rb_td!r}; expected {td_v1!r}"
    assert _svc(ecs, cluster, svc)["taskDefinition"] == td_v1, (
        f"service did not revert to {td_v1!r} after the accepted stop")
    triggered = (done.get("alarms") or {}).get("triggeredAlarmNames") or []
    assert triggered == [], f"a manual stop reported triggered alarms {triggered!r}"


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly SUCCEEDED; expected it to be rejected")


def _describe(ecs, arns: list[str]) -> list[dict]:
    return ecs.describe_service_deployments(serviceDeploymentArns=arns)["serviceDeployments"]


def _deployments(ecs, cluster: str, service: str) -> list[dict]:
    arns, token = [], None
    while True:
        kw = {"cluster": cluster, "service": service}
        if token:
            kw["nextToken"] = token
        page = ecs.list_service_deployments(**kw)
        arns += [d["serviceDeploymentArn"] for d in page.get("serviceDeployments", [])]
        token = page.get("nextToken")
        if not token:
            break
    return _describe(ecs, arns) if arns else []


def _svc(ecs, cluster: str, service: str) -> dict:
    return ecs.describe_services(cluster=cluster, services=[service])["services"][0]


def _delete_service(ecs, cluster: str, service: str) -> None:
    try:
        ecs.delete_service(cluster=cluster, service=service, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in {"ServiceNotFoundException", "ServiceNotActiveException"}:
            raise


def _retry_cluster_delete(ecs, cluster: str) -> None:
    deadline = time.monotonic() + 120.0
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f"ECS cluster {cluster}: {code}") from exc
            time.sleep(5.0)


def _delete_task_definitions(ecs, tds: list[str]) -> None:
    live = []
    for td in tds:
        try:
            status = ecs.describe_task_definition(taskDefinition=td)["taskDefinition"]["status"]
        except ClientError as exc:
            if "Unable to describe task definition" not in exc.response["Error"].get("Message", ""):
                raise
            continue
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=td)
        if status != "DELETE_IN_PROGRESS":
            live.append(td)
    if live:
        failures = ecs.delete_task_definitions(taskDefinitions=live).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition teardown failed: {failures}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    delay = interval_s
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(delay)
        delay = min(delay * 1.5, 30.0)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
