"""alarm-rollback-returns-live-traffic-to-prior-version."""
from __future__ import annotations

import io
import json
import textwrap
import threading
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "alarm-rollback-returns-live-traffic-to-prior-version"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
CANARY_PERCENTAGE = 10
CANARY_INTERVAL_MINUTES = 1
# Driving the associated alarm to ALARM while the deployment is InProgress moves it to a
# terminal state in about 20 s; the deployment ends 'Stopped' (not 'Failed'),
# errorInformation.code is ALARM_ACTIVE and names the alarm, and rollbackInfo on the stopped
# deployment carries rollbackDeploymentId -- while rollbackTriggeringDeploymentId lives on the
# ROLLBACK deployment, pointing the other way.
_ROLLED_BACK_STATUS = "Stopped"
_ROLLED_BACK_CODE = "ALARM_ACTIVE"
_ROLLBACK_CREATOR = "codeDeployRollback"

# --- the continuous requester ------------------------------------------------------------- #
# See the docstring: the graded output of this check is a CESSATION of a traffic pattern, so
# there has to be a traffic pattern to cease. 8 workers x 0.4 s ~= 20 requests/second.
WORKERS = 8
INTERVAL_S = 0.4
SAMPLER_INTERVAL_S = 2.0
# After a weight is written to a live alias the first invoke honours it within about 1 s, and
# every 200-invoke sample from then on reads the new distribution. 5 s, applied to both edges
# of every window, leaves a wide margin.
TRIM_S = 5.0
N_MIN = 200
PRE_TARGET = 500
# How many observations must land inside the canary window BEFORE the alarm is driven to
# ALARM. This is what makes the check non-vacuous: if no live invoke ever reached the new
# version, the rollback has nothing to undo and the whole check would be measuring an absence
# that was already there. It is an ASSERTION, not a retry.
BREACH_OBSERVE_TARGET = 300
CANARY_SHARE_MAX = 0.35
# B -- the total budget from set_alarm_state(ALARM) to the invoke path no longer reaching the
# rolled-back version. Deliberately generous: about 20 s of that is the control-plane
# transition to terminal, the rollback deployment then has to run, and the invoke path's own
# propagation follows. The check reports the value it actually measured in the assert message.
ROLLBACK_BOUND_S = 150.0

CODE = """\
def handler(event, context):
    return {"marker": "%s"}
"""


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """When a CloudWatch alarm breaches mid-canary, live invokes stop reaching the new version and
    every later invoke reaches the version the deployment started from, with no failed request:
    a rollback that only rewrites the alias record leaves live traffic on the broken version."""
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")
    # ONE shared client for the requester and the sampler, built here on the MAIN thread; the
    # pool is widened so the worker threads never wait for a connection.
    inv = ctx.client("lambda", config=Config(max_pool_connections=WORKERS + 4))

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"
    marker_of = {v1: "v1", v2: "v2", v3: "v3"}

    alarm = ctx.unique_name("sim2real-behav-cd-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm,
        # A namespace that never receives a datapoint: nothing to leave behind, and the alarm's
        # state is therefore entirely under SetAlarmState's control.
        Namespace="sim2real/codedeploy/no-datapoints",
        MetricName="never-published",
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmDescription="sim2real codedeploy auto-rollback trigger",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_alarm(cw, alarm))

    app = _create_application(ctx, compute_platform="Lambda")
    cfg = _create_deployment_config(
        ctx, compute_platform="Lambda",
        traffic_routing_config={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {"canaryPercentage": CANARY_PERCENTAGE,
                                "canaryInterval": CANARY_INTERVAL_MINUTES},
        })
    dg = _create_deployment_group(
        ctx, app, deployment_config=cfg,
        alarmConfiguration={"enabled": True, "alarms": [{"name": alarm}]},
        autoRollbackConfiguration={"enabled": True,
                                   "events": ["DEPLOYMENT_STOP_ON_ALARM"]})
    group_info = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg)["deploymentGroupInfo"]
    assert [a["name"] for a in group_info.get("alarmConfiguration", {}).get("alarms", [])] \
        == [alarm], (
        f"the deployment group echoed alarmConfiguration "
        f"{group_info.get('alarmConfiguration')!r}, expected exactly the alarm {alarm!r}"
    )
    assert group_info.get("autoRollbackConfiguration", {}).get("events") == \
        ["DEPLOYMENT_STOP_ON_ALARM"], (
        f"the deployment group echoed autoRollbackConfiguration "
        f"{group_info.get('autoRollbackConfiguration')!r}, expected events "
        f"['DEPLOYMENT_STOP_ON_ALARM']"
    )

    # --- the continuous requester and the independent weight sampler ---
    # Registered as cleanup BEFORE the threads start and AFTER every create above, so LIFO runs
    # it FIRST at teardown: a mid-check assertion failure must not leave workers invoking a
    # function the cleanup behind them is deleting.
    traffic = _Traffic(inv, lam, fn, alias, marker_of)
    ctx.on_cleanup(traffic.stop)
    traffic.start()
    traffic.wait_for_observations(PRE_TARGET, timeout_s=180)

    # ================= positive control leg: the alarm at OK ================= #
    _force_alarm_state(cw, alarm, "OK")
    ctrl_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, deploymentConfigName=cfg,
        revision=_lambda_revision(fn, alias, v1, v2))["deploymentId"]
    _register_deployment_teardown(ctx, cd, ctrl_id)
    t_ctrl_weighted = traffic.wait_for_weight_event(
        lambda w: bool(w), timeout_s=180)
    assert t_ctrl_weighted is not None, (
        f"positive control: no AdditionalVersionWeights ever appeared on {alias!r} while "
        f"{ctrl_id!r} ran; the sampler saw {traffic.weight_log()[-6:]!r}. Without a canary "
        f"window there is nothing for the breach leg to interrupt"
    )
    ctrl_info = _poll(lambda: cd.get_deployment(deploymentId=ctrl_id)["deploymentInfo"],
                      lambda i: i.get("status") in TERMINAL,
                      timeout_s=420, interval_s=3)
    assert ctrl_info.get("status") == "Succeeded", (
        f"positive control: with the alarm at OK the canary deployment {ctrl_id!r} ended "
        f"{ctrl_info.get('status')!r} with errorInformation "
        f"{ctrl_info.get('errorInformation')!r}; the alarm state cannot be isolated until this "
        f"leg passes"
    )
    t_ctrl_cleared = traffic.wait_for_weight_event(
        lambda w: not w, timeout_s=240, after=t_ctrl_weighted)
    assert t_ctrl_cleared is not None, (
        f"positive control: the weights never cleared off {alias!r} after {ctrl_id!r} "
        f"succeeded; the sampler saw {traffic.weight_log()[-6:]!r}"
    )
    traffic.wait_for_observations_after(t_ctrl_cleared + TRIM_S, N_MIN,
                                        timeout_s=120)

    obs = traffic.snapshot()
    ctrl_pre = [o for o in obs if o[0] < t_ctrl_weighted - TRIM_S]
    ctrl_post = [o for o in obs if o[0] > t_ctrl_cleared + TRIM_S]
    assert len(ctrl_pre) >= N_MIN and len(ctrl_post) >= N_MIN, (
        f"positive control: the pre-shift window holds {len(ctrl_pre)} observations and the "
        f"post-cutover window {len(ctrl_post)}, needing {N_MIN} each; the requester produced "
        f"{len(obs)} in total and the canary spanned "
        f"{t_ctrl_weighted:.1f}s..{t_ctrl_cleared:.1f}s"
    )
    assert set(_tally(ctrl_pre)) == {v1}, (
        f"positive control: before any weight appeared, all {len(ctrl_pre)} invokes must "
        f"execute {v1!r}; they executed {_tally(ctrl_pre)!r}"
    )
    assert set(_tally(ctrl_post)) == {v2}, (
        f"positive control: after the un-breached canary completed, all {len(ctrl_post)} "
        f"invokes must execute {v2!r}; they executed {_tally(ctrl_post)!r}. The control leg "
        f"has to move traffic before a leg that stops it can mean anything"
    )

    # ================= breach leg: break exactly one thing, the alarm's state ============= #
    t_breach_created = traffic.now()
    breach_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, deploymentConfigName=cfg,
        revision=_lambda_revision(fn, alias, v2, v3))["deploymentId"]
    _register_deployment_teardown(ctx, cd, breach_id)
    running = _poll(lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
                    lambda i: i.get("status") == "InProgress" or i.get("status") in TERMINAL,
                    timeout_s=180, interval_s=2)
    assert running.get("status") == "InProgress", (
        f"the deployment reached {running.get('status')!r} before the canary window opened, so "
        f"there was nothing for the alarm to interrupt; a {CANARY_INTERVAL_MINUTES}-minute "
        f"canary must not complete immediately"
    )
    t_breach_weighted = traffic.wait_for_weight_event(
        lambda w: bool(w), timeout_s=180, after=t_breach_created)
    assert t_breach_weighted is not None, (
        f"no AdditionalVersionWeights appeared on {alias!r} while {breach_id!r} ran; the "
        f"sampler saw {traffic.weight_log()[-6:]!r}"
    )

    # --- the vacuity guard: live traffic really was reaching the new version --- #
    traffic.wait_for_observations_after(t_breach_weighted + TRIM_S, BREACH_OBSERVE_TARGET,
                                        timeout_s=120)
    _force_alarm_state(cw, alarm, "ALARM")
    t_breach = traffic.now()

    pre_breach = [o for o in traffic.snapshot()
                  if t_breach_weighted + TRIM_S <= o[0] <= t_breach]
    pre_breach_counts = _tally(pre_breach)
    k3 = pre_breach_counts.get(v3, 0)
    n_pb = len(pre_breach)
    assert set(pre_breach_counts) <= {v2, v3}, (
        f"during the canary the only versions reachable through {alias!r} are the current "
        f"{v2!r} and the target {v3!r}; observed {pre_breach_counts!r}"
    )
    assert k3 >= 1, (
        f"NOT ONE of the {n_pb} invokes taken inside the canary window before the breach "
        f"executed {v3!r} (observed {pre_breach_counts!r}), while the alias carried "
        f"AdditionalVersionWeights of {CANARY_PERCENTAGE / 100.0}. The rollback would then "
        f"have nothing to undo and this check would prove nothing -- so this is an assertion, "
        f"not a retry. At a nominal share of {CANARY_PERCENTAGE / 100.0} over {n_pb} invokes "
        f"the probability of observing none is below 7.1e-10, so the dispatcher is not reading "
        f"the weight CodeDeploy wrote"
    )
    assert k3 / n_pb < CANARY_SHARE_MAX, (
        f"{k3} of {n_pb} invokes before the breach executed {v3!r}, a share of "
        f"{k3 / n_pb:.3f}; a {CANARY_PERCENTAGE}% canary must stay below {CANARY_SHARE_MAX}"
    )

    # --- control-plane assertions on the stopped and rollback deployments --- #
    stopped = _poll(lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
                    lambda i: i.get("status") in TERMINAL,
                    timeout_s=300, interval_s=3)
    assert stopped.get("status") == _ROLLED_BACK_STATUS, (
        f"a deployment stopped by an alarm breach must end {_ROLLED_BACK_STATUS!r}, got "
        f"{stopped.get('status')!r} with errorInformation {stopped.get('errorInformation')!r}"
    )
    err = stopped.get("errorInformation") or {}
    assert err.get("code") == _ROLLED_BACK_CODE, (
        f"expected errorInformation code {_ROLLED_BACK_CODE!r} after an alarm breach, got "
        f"{err!r}"
    )
    assert alarm in (err.get("message") or ""), (
        f"the failure must name the alarm that activated; expected {alarm!r} in "
        f"{err.get('message')!r}"
    )
    # MEASURED: rollbackInfo is populated a beat AFTER the deployment first reads terminal, so
    # this polls an observable condition rather than reading the terminal snapshot.
    attributed = _poll(
        lambda: cd.get_deployment(deploymentId=breach_id)["deploymentInfo"],
        lambda i: bool((i.get("rollbackInfo") or {}).get("rollbackDeploymentId")),
        timeout_s=180, interval_s=3)
    rollback_id = (attributed.get("rollbackInfo") or {}).get("rollbackDeploymentId")
    assert rollback_id, (
        f"the stopped deployment must name the rollback it spawned in "
        f"rollbackInfo.rollbackDeploymentId; it reads {attributed.get('rollbackInfo')!r}"
    )
    assert breach_id in (attributed.get("rollbackInfo") or {}).get("rollbackMessage", ""), (
        f"the rollbackMessage must name the deployment that was terminated ({breach_id!r}); it "
        f"reads {(attributed.get('rollbackInfo') or {}).get('rollbackMessage')!r}"
    )
    _register_deployment_teardown(ctx, cd, rollback_id)
    rollback = cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"]
    assert rollback.get("creator") == _ROLLBACK_CREATOR, (
        f"the rollback deployment {rollback_id!r} must be attributed to "
        f"{_ROLLBACK_CREATOR!r}, not {rollback.get('creator')!r}; a rollback the service "
        f"performed on its own is not a user deployment"
    )
    assert (rollback.get("rollbackInfo") or {}).get("rollbackTriggeringDeploymentId") == \
        breach_id, (
        f"the rollback deployment must point back at the deployment that triggered it "
        f"({breach_id!r}); its rollbackInfo reads {rollback.get('rollbackInfo')!r}"
    )
    assert rollback_id != breach_id, (
        f"the rollback must be a separate deployment record, not the same id {breach_id!r}"
    )
    restored = _poll(lambda: lam.get_alias(FunctionName=fn, Name=alias),
                     lambda a: a.get("FunctionVersion") == v2
                     and not (a.get("RoutingConfig") or {}).get("AdditionalVersionWeights"),
                     timeout_s=240, interval_s=3)
    assert restored["FunctionVersion"] == v2, (
        f"the auto-rollback must restore the alias to the version the interrupted deployment "
        f"started from ({v2!r}), it reads {restored['FunctionVersion']!r}"
    )
    assert not (restored.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"the auto-rollback must clear the canary weight it had already applied: {restored!r}"
    )

    # ================= the effect this check exists for: traffic ceased ================== #
    # Wait for the post-rollback window to fill, measured from the LAST observation that
    # reached the rolled-back version rather than from any control-plane timestamp -- the
    # cessation is the subject, so it dates its own window.
    def _tail_count():
        """Observations landing more than TRIM_S after the LAST invoke that reached v3. The
        cutoff moves forward every time another v3 lands, so this cannot be satisfied while
        traffic is still reaching the rolled-back version."""
        rows = traffic.snapshot()
        hits = [o[0] for o in rows if o[1] == v3]
        if not hits:
            return 0
        cutoff = max(hits) + TRIM_S
        return len([o for o in rows if o[0] > cutoff])

    _poll(_tail_count, lambda c: c >= 2 * N_MIN,
          timeout_s=240, interval_s=3)
    traffic.stop()
    final = traffic.snapshot()

    # Zero-error across the whole run, INCLUDING the rollback instant. A rollback that drops
    # requests fails here and passes every assertion in the check this one extends.
    bad = [o for o in final if o[3] is not None]
    assert not bad, (
        f"{len(bad)} of {len(final)} invokes taken across the control leg, the canary, the "
        f"breach and the rollback were not a clean 200 whose returned marker matched its "
        f"ExecutedVersion. First three: {bad[:3]!r}. A rollback that drops or errors requests "
        f"is not a rollback a customer can survive"
    )

    v3_times = [o[0] for o in final if o[1] == v3]
    assert v3_times, (
        f"no observation anywhere in the run executed {v3!r}; the vacuity guard above should "
        f"have caught this"
    )
    t_stop = max(v3_times)
    measured_b = t_stop - t_breach
    assert measured_b <= ROLLBACK_BOUND_S, (
        f"the last invoke to execute the rolled-back version {v3!r} landed {measured_b:.1f}s "
        f"after the alarm was driven to ALARM, above the {ROLLBACK_BOUND_S}s bound. CodeDeploy "
        f"reported {_ROLLED_BACK_STATUS!r} and the alias reads {v2!r}, so the record and the "
        f"traffic disagree: the dispatcher is still serving the version the rollback replaced"
    )
    tail = [o for o in final if o[0] > t_stop + TRIM_S]
    assert len(tail) >= 2 * N_MIN, (
        f"only {len(tail)} observations landed more than {TRIM_S}s after the last {v3!r} "
        f"invoke (at t={t_stop:.1f}s), needing {2 * N_MIN} to bound the cessation"
    )
    tail_counts = _tally(tail)
    assert set(tail_counts) == {v2}, (
        f"every one of the {len(tail)} invokes taken after the rollback took effect must "
        f"execute {v2!r}, the version the interrupted deployment started from; they executed "
        f"{tail_counts!r}. THIS is the assertion an emulator that rewrites the alias record "
        f"without re-reading it in the dispatcher fails, while passing every control-plane "
        f"assertion above"
    )

    # The record and the traffic must agree on WHEN the rollback happened, in both directions.
    t_weights_gone = traffic.first_weight_event(lambda w: not w, after=t_breach)
    assert t_weights_gone is not None, (
        f"the sampler never observed the weights clear off {alias!r} after the breach; it saw "
        f"{traffic.weight_log()[-6:]!r}"
    )
    assert abs(t_stop - t_weights_gone) <= ROLLBACK_BOUND_S, (
        f"the last {v3!r} invoke (t={t_stop:.1f}s) and the first alias sample with the weights "
        f"cleared (t={t_weights_gone:.1f}s) are {abs(t_stop - t_weights_gone):.1f}s apart, "
        f"above the {ROLLBACK_BOUND_S}s bound; the alias record and the dispatch path do not "
        f"agree on when the rollback happened"
    )
    ids = _list_group_deployments(cd, app, dg)
    assert {ctrl_id, breach_id, rollback_id} <= set(ids), (
        f"the paginated deployment listing {ids!r} does not contain the control {ctrl_id!r}, "
        f"the interrupted deployment {breach_id!r} and the rollback {rollback_id!r}"
    )


# ===== helpers =====

class _Traffic:
    """A continuous requester against a Lambda alias, plus an INDEPENDENT weight sampler.

    The two are deliberately separate. The requester records what actually executed; the
    sampler records what the alias record said, on its own cadence. Windows are dated by the
    SAMPLER, so a target cannot satisfy a window assertion by reporting whatever the requester
    happens to be asking for -- the boundaries come from a different observation than the one
    being graded.

    Every row is (t_relative_seconds, executed_version, marker, failure_or_None).
    """

    def __init__(self, inv, lam, fn, alias, marker_of):
        self._inv = inv
        self._lam = lam
        self._fn = fn
        self._alias = alias
        self._marker_of = marker_of
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._obs = []
        self._weights = []
        self._threads = []
        self._t0 = None

    # --- lifecycle ---
    def start(self):
        self._t0 = time.monotonic()
        self._threads = [threading.Thread(target=self._sampler, daemon=True)]
        self._threads += [threading.Thread(target=self._driver, daemon=True)
                          for _ in range(WORKERS)]
        for t in self._threads:
            t.start()

    def stop(self):
        """Idempotent, and safe to call from cleanup: a mid-check assertion failure must not
        leave workers invoking a function the teardown behind them is deleting."""
        self._stop.set()
        for t in self._threads:
            t.join(timeout=30)
        self._threads = []

    def now(self):
        return time.monotonic() - self._t0

    # --- the threads ---
    def _driver(self):
        while not self._stop.is_set():
            t = time.monotonic() - self._t0
            executed, marker, failure = _invoke_once(
                self._inv, self._fn, self._alias, self._marker_of)
            with self._lock:
                self._obs.append((t, executed, marker, failure))
            self._stop.wait(INTERVAL_S)

    def _sampler(self):
        while not self._stop.is_set():
            t = time.monotonic() - self._t0
            try:
                a = self._lam.get_alias(FunctionName=self._fn, Name=self._alias)
                row = (t, a.get("FunctionVersion"),
                       dict((a.get("RoutingConfig") or {}).get(
                           "AdditionalVersionWeights") or {}), None)
            except ClientError as exc:
                row = (t, None, {}, exc.response.get("Error", {}).get("Code"))
            with self._lock:
                self._weights.append(row)
            self._stop.wait(SAMPLER_INTERVAL_S)

    # --- reads ---
    def snapshot(self):
        with self._lock:
            return list(self._obs)

    def weight_log(self):
        with self._lock:
            return list(self._weights)

    def wait_for_observations(self, n, *, timeout_s):
        got = _poll(lambda: len(self.snapshot()), lambda c: c >= n,
                    timeout_s=timeout_s, interval_s=1)
        assert got >= n, (
            f"the requester produced only {got} observations within {timeout_s}s, needing "
            f"{n}; at {WORKERS} workers x {INTERVAL_S}s it should manage ~"
            f"{WORKERS / INTERVAL_S:.0f}/s"
        )
        return got

    def wait_for_observations_after(self, t_from, n, *, timeout_s):
        got = _poll(lambda: len([o for o in self.snapshot() if o[0] > t_from]),
                    lambda c: c >= n, timeout_s=timeout_s, interval_s=1)
        assert got >= n, (
            f"only {got} observations landed after t={t_from:.1f}s within {timeout_s}s, "
            f"needing {n}"
        )
        return got

    def first_weight_event(self, pred, *, after=None):
        """The timestamp of the first sampler row already recorded whose weights satisfy
        ``pred``, or None."""
        for t, _primary, weights, failure in self.weight_log():
            if failure is not None:
                continue
            if after is not None and t <= after:
                continue
            if pred(weights):
                return t
        return None

    def wait_for_weight_event(self, pred, *, timeout_s, after=None):
        """As ``first_weight_event``, polled until it appears or the deadline passes."""
        return _poll(lambda: self.first_weight_event(pred, after=after),
                     lambda v: v is not None, timeout_s=timeout_s,
                     interval_s=SAMPLER_INTERVAL_S)


def _tally(window):
    counts = {}
    for _t, executed, _marker, _failure in window:
        counts[executed] = counts.get(executed, 0) + 1
    return counts


def _invoke_once(inv, fn, alias, marker_of):
    """One alias invoke, reduced to what the assertions need.

    The tuple carries both halves of the version claim: the version the service SAYS ran
    (ExecutedVersion) and the marker returned by the code that actually ran. A target that
    synthesises the label without dispatching differently is caught by their disagreement,
    which no count over ExecutedVersion alone could see.
    """
    try:
        r = inv.invoke(FunctionName=f"{fn}:{alias}", Payload=b"{}")
    except ClientError as exc:
        return (None, None, f"ClientError:{exc.response.get('Error', {}).get('Code')}")
    status = r.get("StatusCode")
    executed = r.get("ExecutedVersion")
    if status != 200:
        return (executed, None, f"StatusCode:{status!r}")
    if "FunctionError" in r:
        return (executed, None,
                f"FunctionError:{r['FunctionError']!r}:{r['Payload'].read()[:200]!r}")
    try:
        marker = json.loads(r["Payload"].read()).get("marker")
    except ValueError as exc:
        return (executed, None, f"unparseable payload: {exc}")
    if executed not in marker_of:
        return (executed, marker, f"ExecutedVersion {executed!r} is not a published version")
    if marker != marker_of[executed]:
        return (executed, marker,
                f"ExecutedVersion {executed!r} but the code returned marker {marker!r}")
    return (executed, marker, None)


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _list_group_deployments(cd, app, dg):
    """Every deployment id for the group, paginated."""
    ids, token = [], None
    while True:
        kwargs = {"applicationName": app, "deploymentGroupName": dg}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployments(**kwargs)
        ids.extend(resp.get("deployments") or [])
        token = resp.get("nextToken")
        if not token:
            break
    return ids


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _lambda_exec_role_arn(ctx):
    """An execution role this check creates once per run and deletes in its teardown."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _wait_lambda_active(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("State") == "Failed":
            raise AssertionError(f"{fn} entered Failed: {last.get('StateReason')}")
        if last.get("State") == "Active" and \
                last.get("LastUpdateStatus", "Successful") == "Successful":
            return
        time.sleep(2)
    raise AssertionError(f"{fn} never became Active within {timeout_s}s. Last: {last!r}")


def _cleanup_function(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_log_group(ctx, f"/aws/lambda/{name}")


def _delete_log_group(ctx, group, appear_s=90, timeout_s=120, quiet_s=15):
    """Wait for the Lambda log group to exist, then delete it and KEEP it deleted.

    The group is created by the SERVICE on first invocation, so a single delete races it: the
    group can appear after the delete (so this waits for it to APPEAR first), and CloudWatch Logs
    recreates a deleted group when late log events arrive (so the delete repeats until the group
    has stayed absent for ``quiet_s``).
    """
    logs = ctx.client("logs")

    def _present():
        return any(g.get("logGroupName") == group
                   for g in logs.describe_log_groups(
                       logGroupNamePrefix=group).get("logGroups", []))

    appear_deadline = time.monotonic() + appear_s
    while not _present():
        if time.monotonic() >= appear_deadline:
            # It genuinely never materialised (a check that never invoked). Nothing to delete.
            return
        time.sleep(5)

    deadline = time.monotonic() + timeout_s
    absent_since = None
    while True:
        if _present():
            absent_since = None
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        elif absent_since is None:
            absent_since = time.monotonic()
        elif time.monotonic() - absent_since >= quiet_s:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"log group {group!r} was still reappearing after {timeout_s}s of deletes; it "
                f"is leaking"
            )
        time.sleep(5)


def _publish_version(lam, fn, n):
    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip(CODE % f"v{n}"))
    _wait_lambda_active(lam, fn)
    return lam.publish_version(FunctionName=fn, Description=f"v{n}")["Version"]


def _versioned_function_with_alias(ctx, lam, alias_name="live"):
    name = ctx.unique_name("sim2real-behav-cd-fn-")
    _create_function(lam,
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_lambda_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip(CODE % "v1")},
        MemorySize=128,
        Timeout=10,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, name))
    _wait_lambda_active(lam, name)
    v1 = lam.publish_version(FunctionName=name, Description="v1")["Version"]
    v2 = _publish_version(lam, name, 2)
    assert v1 != v2, f"publish_version returned the same version twice: {v1!r}"
    lam.create_alias(FunctionName=name, Name=alias_name, FunctionVersion=v1)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=name, Name=alias_name))
    return name, v1, v2, alias_name


def _appspec_body(fn, alias, current_version, target_version):
    """The AppSpec CodeDeploy parses to decide which alias to move, and from/to where."""
    return {
        "version": 0.0,
        "Resources": [
            {
                fn: {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Name": fn,
                        "Alias": alias,
                        "CurrentVersion": current_version,
                        "TargetVersion": target_version,
                    },
                }
            }
        ],
    }


def _lambda_revision(fn, alias, current_version, target_version):
    return {
        "revisionType": "AppSpecContent",
        "appSpecContent": {
            "content": json.dumps(_appspec_body(fn, alias, current_version, target_version))
        },
    }


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _create_deployment_config(ctx, *, compute_platform, traffic_routing_config=None):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-cfg-")
    kwargs = {"deploymentConfigName": name, "computePlatform": compute_platform}
    if traffic_routing_config is not None:
        kwargs["trafficRoutingConfig"] = traffic_routing_config
    cd.create_deployment_config(**kwargs)
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _make_codedeploy_role(ctx, prefix, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codedeploy.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM exposes no condition reporting that a policy has become effective, so a short fixed
    # sleep is used; the bounded InvalidRoleException retry in
    # _create_deployment_group is what actually makes the check correct.
    time.sleep(12)
    return resp["Role"]["Arn"]


def _create_service_role(ctx):
    cached = getattr(ctx, "_cd_service_role_arn", None)
    if cached:
        return cached
    arn = _make_codedeploy_role(ctx, "sim2real-behav-role-codedeploy-",
                                [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    ctx._cd_service_role_arn = arn
    return arn


def _create_deployment_group(ctx, app, *, deployment_config, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": extra.pop("serviceRoleArn", None) or _create_service_role(ctx),
        "deploymentStyle": {
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
    }
    kwargs.update(extra)
    deadline = time.monotonic() + 75
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidRoleException" and (
                "assume" in msg or "not authorized" in msg or "permissions required" in msg
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name


def _register_deployment_teardown(ctx, cd, dep_id):
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment blocks
    its deployment group's deletion, so this must run before the group's own cleanup (LIFO
    gives that ordering for free)."""
    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("DeploymentAlreadyCompletedException",
                            "InvalidDeploymentStatusException"):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
            if status in TERMINAL:
                return
            time.sleep(5)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown "
            "deadline; the deployment group may block deletion"
        )

    ctx.on_cleanup(_teardown)


def _force_alarm_state(cw, alarm, want, timeout_s=60):
    """SetAlarmState, then poll DescribeAlarms until the alarm really reads that state.
    SetAlarmState is asynchronous: returning is not the same as CodeDeploy being able to
    observe the new state, and a check that assumed it was would breach the alarm after the
    window it meant to breach."""
    cw.set_alarm_state(AlarmName=alarm, StateValue=want,
                       StateReason="sim2real: driving the CodeDeploy rollback trigger")
    got = _poll(lambda: cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"][0],
                lambda a: a.get("StateValue") == want, timeout_s=timeout_s, interval_s=2)
    assert got.get("StateValue") == want, (
        f"the alarm {alarm!r} did not reach {want!r} within {timeout_s}s; it reads "
        f"{got.get('StateValue')!r}, so the deployment would not see the state this check "
        f"intends to test"
    )


def _delete_alarm(cw, alarm, timeout_s=90):
    """Delete the alarm and CONFIRM it is gone, retrying. ctx.on_cleanup swallows whatever this
    raises, so a delete that is transiently refused while CodeDeploy still has the alarm
    associated would otherwise leak in silence."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cw.delete_alarms(AlarmNames=[alarm])
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
            continue
        if not cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"]:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"alarm {alarm!r} still present after {timeout_s}s of delete attempts"
            )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
