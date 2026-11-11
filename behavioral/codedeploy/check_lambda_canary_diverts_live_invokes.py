"""lambda-canary-diverts-live-invokes."""
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

CHECK = "lambda-canary-diverts-live-invokes"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
CANARY_PERCENTAGE = 10
CANARY_INTERVAL_MINUTES = 1
HOOK_EVENT = "BeforeAllowTraffic"

# --- the continuous requester ------------------------------------------------------------- #
#
# 8 workers x 0.4 s ~= 20 requests/second. The point of the rate is not throughput: it is that
# every assertion below is made over a WINDOW whose boundaries come from an independent
# observer -- a separate thread sampling GetAlias every 2 s -- rather than over a global tally.
# A global tally across a traffic shift is meaningless, because the true weight changes
# underneath it.
WORKERS = 8
INTERVAL_S = 0.4
SAMPLER_INTERVAL_S = 2.0
# Each window is trimmed by this much on both sides to absorb the invoke path's propagation
# lag. The invoke path honours a new alias weight within about a second;
# 5 s is a bound, not an encoding of it.
TRIM_S = 5.0
# The minimum observations a window must hold before it may be asserted on. At p=0.10,
# P(k = 0 | N = 200) = 0.9**200 = 7.06e-10, so "at least one invoke reached the canary" is a
# one-in-a-billion assertion rather than a flaky one. Computed offline:
#     0.9 ** 200 -> 7.055e-10
N_MIN = 200
# How many observations to bank BEFORE creating the deployment. The pre-shift window is
# everything before (first weighted sample - TRIM_S), so it loses its tail twice over: to the
# trim, and to the few seconds between CreateDeployment returning and the weight appearing.
# That is why PRE_TARGET exceeds N_MIN: 500 observations is ~25s at the rate
# below, so ~9s of loss still leaves well over N_MIN.
PRE_TARGET = 500
# The canary share must be a MINORITY and the primary must carry the BULK. Both are ratio
# assertions rather than bands, because a timed window's N is not known in advance; at p=0.10
# and N>=200 the probability of exceeding 0.35 is smaller than the band tails above.
# NOTHING HERE ASSERTS AN EXACT SPLIT. The discrimination comes from the ORDERING of three
# phases measured in one run: share(pre) == 0 < share(canary) < share(post) == 1.
CANARY_SHARE_MAX = 0.35
PRIMARY_SHARE_MIN = 0.55
# The canary interval is real clock time.
CANARY_ELAPSED_MIN_S = 50.0

CODE = """\
def handler(event, context):
    return {"marker": "%s"}
"""

_HOOK_SRC = """
import os
import boto3


def handler(event, context):
    boto3.client("codedeploy").put_lifecycle_event_hook_execution_status(
        deploymentId=event["DeploymentId"],
        lifecycleEventHookExecutionId=event["LifecycleEventHookExecutionId"],
        status=os.environ["HOOK_STATUS"],
    )
    return {"reported": os.environ["HOOK_STATUS"]}
"""


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-configurations.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A TimeBasedCanary deployment diverts live invokes: during the canary window a minority
    of alias invokes run the target version's code, after cutover all do, and a deployment
    whose BeforeAllowTraffic hook reports Failed moves no traffic at all."""
    cd = ctx.client("codedeploy")
    lam = ctx.client("lambda")
    # ONE shared client for the requester and the sampler, built here on the MAIN thread.
    # ctx.client caches per (service, endpoint, region, config, creds) behind a lock, so every
    # thread below is handed this same client; botocore clients are safe to CALL concurrently,
    # and the pool must be wider than the worker count or they serialise on it.
    inv = ctx.client("lambda", config=Config(max_pool_connections=WORKERS + 4))

    fn, v1, v2, alias = _versioned_function_with_alias(ctx, lam)
    v3 = _publish_version(lam, fn, 3)
    assert len({v1, v2, v3}) == 3, f"setup: versions collided: {(v1, v2, v3)!r}"
    marker_of = {v1: "v1", v2: "v2", v3: "v3"}

    hook_exec = _create_hook_exec_role(ctx)
    hook_bad = _create_hook_function(ctx, lam, hook_exec, "Failed")

    app = _create_application(ctx, compute_platform="Lambda")
    cfg = _create_deployment_config(
        ctx, compute_platform="Lambda",
        traffic_routing_config={
            "type": "TimeBasedCanary",
            "timeBasedCanary": {"canaryPercentage": CANARY_PERCENTAGE,
                                "canaryInterval": CANARY_INTERVAL_MINUTES},
        })
    dg = _create_deployment_group(ctx, app, deployment_config=cfg)

    # --- the continuous requester and the independent weight sampler ---
    # Registered as cleanup BEFORE the threads start, and registered AFTER every create above,
    # so LIFO runs it FIRST at teardown: a mid-check assertion failure must not leave workers
    # invoking a function the cleanup behind them is deleting.
    traffic = _Traffic(inv, lam, fn, alias, marker_of)
    ctx.on_cleanup(traffic.stop)
    traffic.start()

    # --- phase 1: the pre-shift baseline. Everything must reach the current version. ---
    traffic.wait_for_observations(PRE_TARGET, timeout_s=180)

    # --- the deployment. CodeDeploy owns the alias from here. ---
    dep_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, deploymentConfigName=cfg,
        revision=_lambda_revision(fn, alias, v1, v2))["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)

    # The sampler is the independent observer that dates the windows. Its first WEIGHTED sample
    # opens the canary window; its first sample with the weights gone closes it.
    t_weighted = traffic.wait_for_weight_event(
        lambda weights: bool(weights), timeout_s=180)
    assert t_weighted is not None, (
        f"no AdditionalVersionWeights ever appeared on {alias!r} while deployment {dep_id!r} "
        f"ran; the alias sampler saw {traffic.weight_log()[-6:]!r}. A deployment that jumps "
        f"straight to the target version is not implementing TimeBasedCanary, and there is no "
        f"canary window in which to observe diverted traffic"
    )
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=420, interval_s=3)
    assert info.get("status") == "Succeeded", (
        f"the canary deployment {dep_id!r} ended {info.get('status')!r} with errorInformation "
        f"{info.get('errorInformation')!r}; the traffic assertions below describe a completed "
        f"shift"
    )
    t_cleared = traffic.wait_for_weight_event(
        lambda weights: not weights, timeout_s=240,
        after=t_weighted)
    assert t_cleared is not None, (
        f"the weights never cleared off {alias!r} after deployment {dep_id!r} reached "
        f"Succeeded; the sampler saw {traffic.weight_log()[-6:]!r}"
    )

    # --- phase 3: let the post-cutover window fill, then stop the requester ---
    traffic.wait_for_observations_after(t_cleared + TRIM_S, N_MIN,
                                        timeout_s=120)
    obs = traffic.snapshot()

    # --- the windows, dated by the sampler and trimmed by the measured bound ---
    pre = [o for o in obs if o[0] < t_weighted - TRIM_S]
    canary = [o for o in obs if t_weighted + TRIM_S <= o[0] <= t_cleared - TRIM_S]
    post = [o for o in obs if o[0] > t_cleared + TRIM_S]
    for label, window in (("pre-shift", pre), ("canary", canary),
                          ("post-cutover", post)):
        assert len(window) >= N_MIN, (
            f"the {label} window holds only {len(window)} observations, below the {N_MIN} the "
            f"assertions need; the requester produced {len(obs)} in total, the canary window "
            f"spanned {t_weighted:.1f}s..{t_cleared:.1f}s and each window is trimmed "
            f"{TRIM_S}s on both sides"
        )

    # --- zero-error and zero-mismatch, across EVERY observation in the run ---
    # The other half of every assertion pair. A target that "shifts" traffic by dropping
    # requests, or that reports a version it did not run, fails here rather than in a count.
    bad = [o for o in obs if o[3] is not None]
    assert not bad, (
        f"{len(bad)} of {len(obs)} invokes taken across the whole deployment were not a clean "
        f"200 whose returned marker matched its ExecutedVersion. First three: {bad[:3]!r}. A "
        f"traffic shift that drops or errors requests is not zero-downtime, however correctly "
        f"it moves the alias"
    )

    # --- phase ordering: the discriminator ---
    pre_counts = _tally(pre)
    assert set(pre_counts) == {v1}, (
        f"before any weight appeared on {alias!r}, all {len(pre)} invokes must execute the "
        f"current version {v1!r}; they executed {pre_counts!r}"
    )
    post_counts = _tally(post)
    assert set(post_counts) == {v2}, (
        f"after the cutover cleared the weights, all {len(post)} invokes must execute the "
        f"target version {v2!r}; they executed {post_counts!r}"
    )
    canary_counts = _tally(canary)
    n = len(canary)
    k2 = canary_counts.get(v2, 0)
    k1 = canary_counts.get(v1, 0)
    assert set(canary_counts) <= {v1, v2}, (
        f"during the canary window the only versions reachable through {alias!r} are the "
        f"current {v1!r} and the target {v2!r}; observed {canary_counts!r}"
    )
    assert k2 >= 1, (
        f"NOT ONE of the {n} invokes taken inside the canary window executed the target "
        f"version {v2!r} (observed {canary_counts!r}), while the alias record carried "
        f"AdditionalVersionWeights of {CANARY_PERCENTAGE / 100.0} throughout. At a nominal "
        f"canary share of {CANARY_PERCENTAGE / 100.0} over {n} >= {N_MIN} invokes the "
        f"probability of that is below 7.1e-10, so this is a dispatcher that never reads the "
        f"weight CodeDeploy wrote -- the weight is decorative"
    )
    assert k2 / n < CANARY_SHARE_MAX, (
        f"{k2} of {n} invokes inside the canary window executed the target {v2!r}, a share of "
        f"{k2 / n:.3f}; a {CANARY_PERCENTAGE}% canary must stay below {CANARY_SHARE_MAX}. A "
        f"target that treats any nonzero weight as a cutover fails here while passing the "
        f"'both versions seen' assertion"
    )
    assert k1 / n > PRIMARY_SHARE_MIN, (
        f"only {k1} of {n} invokes inside the canary window executed the current version "
        f"{v1!r}, a share of {k1 / n:.3f}; during a {CANARY_PERCENTAGE}% canary the primary "
        f"must still carry more than {PRIMARY_SHARE_MIN} of the traffic"
    )
    # The ordering, in SHARES so windows of different length are comparable. This is the
    # discriminator: three configurations of the same alias, measured by the same requester in
    # the same run, must produce three strictly increasing shares. A target that flips the
    # alias atomically produces 0 -> 0 -> 1 and fails here; one that treats any weight as a
    # cutover produces 0 -> 1 -> 1 and fails here too.
    share_pre = len([o for o in pre if o[1] == v2]) / len(pre)
    share_canary = k2 / n
    share_post = len([o for o in post if o[1] == v2]) / len(post)
    assert share_pre < share_canary < share_post, (
        f"the canary share must be strictly between the pre-shift and post-cutover shares of "
        f"{v2!r}: pre {share_pre:.3f} ({_tally(pre)!r}), canary {share_canary:.3f} "
        f"({canary_counts!r}), post {share_post:.3f} ({post_counts!r})"
    )

    # --- the canary interval is real clock time ---
    elapsed = t_cleared - t_weighted
    assert elapsed >= CANARY_ELAPSED_MIN_S, (
        f"the weights were on {alias!r} for only {elapsed:.1f}s, but "
        f"canaryInterval={CANARY_INTERVAL_MINUTES} minute(s) requires at least "
        f"{CANARY_ELAPSED_MIN_S}s. A canary that completes as soon as it is polled enough "
        f"times is a read-count state machine, not a clock"
    )

    # --- the refusal arm: break exactly one thing, the status the hook reports back ---
    n_before_refusal = len(traffic.snapshot())
    bad_id, bad_info = _deploy_and_wait(
        ctx, cd, app, dg, _hook_revision(fn, alias, v2, v3, hook_bad),
        deploymentConfigName="CodeDeployDefault.LambdaAllAtOnce")
    assert bad_info.get("status") == "Failed", (
        f"a deployment whose {HOOK_EVENT} hook reports 'Failed' must end 'Failed'; "
        f"{bad_id!r} ended {bad_info.get('status')!r} with errorInformation "
        f"{bad_info.get('errorInformation')!r}"
    )
    bad_event = _hook_event_status(cd, bad_id)
    assert bad_event == "Failed", (
        f"the {HOOK_EVENT} lifecycle event reads {bad_event!r} on {bad_id!r}, whose hook "
        f"reported 'Failed'; the hook's verdict must be recorded on the event it gated"
    )

    # Effect absent on the control plane.
    unmoved = lam.get_alias(FunctionName=fn, Name=alias)
    assert unmoved["FunctionVersion"] == v2, (
        f"effect not absent: the alias reads {unmoved['FunctionVersion']!r} after a deployment "
        f"its {HOOK_EVENT} hook refused; it must still read {v2!r}"
    )
    assert not (unmoved.get("RoutingConfig") or {}).get("AdditionalVersionWeights"), (
        f"effect not absent: the refused deployment left weighted routing on the alias: "
        f"{unmoved!r}"
    )

    # Effect absent IN TRAFFIC -- the half no existing codedeploy check can see. Let a fresh
    # window fill after the refusal, then assert nothing ever reached the refused version.
    traffic.wait_for_observations(n_before_refusal + N_MIN,
                                  timeout_s=120)
    traffic.stop()
    final = traffic.snapshot()
    refused_hits = [o for o in final if o[1] == v3]
    assert not refused_hits, (
        f"{len(refused_hits)} of {len(final)} invokes executed {v3!r}, the version whose "
        f"deployment was refused at {HOOK_EVENT}. First three: {refused_hits[:3]!r}. A hook "
        f"that gates traffic is not advisory: a refused shift must move NO live traffic, not "
        f"merely leave the alias record unchanged"
    )
    after_refusal = [o for o in final if o[0] > _first_t(final, n_before_refusal)]
    assert set(_tally(after_refusal)) == {v2}, (
        f"every one of the {len(after_refusal)} invokes taken from the refused deployment "
        f"onwards must execute {v2!r}; they executed {_tally(after_refusal)!r}"
    )
    bad_final = [o for o in final if o[3] is not None]
    assert not bad_final, (
        f"{len(bad_final)} of {len(final)} invokes across the whole run, including the refused "
        f"deployment, were not a clean 200 with a matching marker. First three: "
        f"{bad_final[:3]!r}"
    )
    ids = _list_group_deployments(cd, app, dg)
    assert {dep_id, bad_id} <= set(ids), (
        f"the paginated deployment listing {ids!r} does not contain the canary deployment "
        f"{dep_id!r} and the refused one {bad_id!r}"
    )


# ===== helpers =====

class _Traffic:
    """A continuous requester against a Lambda alias, plus an INDEPENDENT weight sampler.

    The two are deliberately separate. The requester records what actually executed; the
    sampler records what the alias record said, on its own cadence. The windows the assertions
    are made over are dated by the SAMPLER, so a target cannot satisfy a window assertion by
    reporting whatever the requester happens to be asking for -- the boundaries come from a
    different observation than the one being graded.

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

    def wait_for_weight_event(self, pred, *, timeout_s, after=None):
        """The timestamp of the first SAMPLER row whose weights satisfy ``pred``, optionally
        restricted to rows after ``after``. Returns None if none appeared in time."""
        def _find():
            for t, _primary, weights, failure in self.weight_log():
                if failure is not None:
                    continue
                if after is not None and t <= after:
                    continue
                if pred(weights):
                    return t
            return None

        return _poll(_find, lambda v: v is not None, timeout_s=timeout_s,
                     interval_s=SAMPLER_INTERVAL_S)


def _tally(window):
    counts = {}
    for _t, executed, _marker, _failure in window:
        counts[executed] = counts.get(executed, 0) + 1
    return counts


def _first_t(obs, index):
    """The timestamp of observation ``index``, or -1 when the run produced fewer than that."""
    return obs[index][0] if index < len(obs) else -1.0


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


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=420, **extra):
    """create_deployment, register its teardown immediately, then poll to a terminal state."""
    dep_id = cd.create_deployment(applicationName=app, deploymentGroupName=dg,
                                  revision=revision, **extra)["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=timeout_s, interval_s=3)
    assert info.get("status") in TERMINAL, (
        f"deployment {dep_id!r} never reached a terminal state; last status "
        f"{info.get('status')!r} with errorInformation {info.get('errorInformation')!r}"
    )
    return dep_id, info


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

    Lambda creates the group some time after the first invoke and CloudWatch Logs recreates a
    deleted group when late log events arrive, so the delete repeats until the group stays
    absent for ``quiet_s``.
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
                f"is leaking and belongs in cleanup.leftovers"
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


def _hook_revision(fn, alias, current_version, target_version, hook_function_name):
    body = _appspec_body(fn, alias, current_version, target_version)
    body["Hooks"] = [{HOOK_EVENT: hook_function_name}]
    return {"revisionType": "AppSpecContent",
            "appSpecContent": {"content": json.dumps(body)}}


def _hook_event_status(cd, dep_id):
    """The HOOK_EVENT lifecycle event's status on the deployment's Lambda target."""
    target_ids, token = [], None
    while True:
        kwargs = {"deploymentId": dep_id}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployment_targets(**kwargs)
        target_ids.extend(resp.get("targetIds") or [])
        token = resp.get("nextToken")
        if not token:
            break
    assert target_ids, f"deployment {dep_id!r} exposed no deployment targets"
    seen = []
    for target_id in target_ids:
        target = cd.get_deployment_target(
            deploymentId=dep_id, targetId=target_id)["deploymentTarget"]
        for event in (target.get("lambdaTarget") or {}).get("lifecycleEvents", []):
            seen.append((event.get("lifecycleEventName"), event.get("status")))
            if event.get("lifecycleEventName") == HOOK_EVENT:
                return event.get("status")
    raise AssertionError(
        f"deployment {dep_id!r} recorded no {HOOK_EVENT} lifecycle event; the events present "
        f"were {seen!r}, so the AppSpec hook was never run"
    )


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
    # IAM exposes no condition reporting that a policy has become effective. Correctness comes
    # entirely from the bounded InvalidRoleException retry in _create_deployment_group, which
    # already covers this propagation delay with a real deadline -- an unconditional sleep here
    # would just be dead weight on top of it.
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


def _create_hook_exec_role(ctx):
    """The execution role for the hook Lambda. It needs exactly one non-default permission:
    the callback CodeDeploy is waiting on."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-hookexec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for arn in [p["PolicyArn"] for p in iam.list_attached_role_policies(
                RoleName=role_name).get("AttachedPolicies", [])]:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-hook-callback",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "codedeploy:PutLifecycleEventHookExecutionStatus",
                "Resource": "*",
            }],
        }),
    )
    # IAM exposes no condition reporting that a role has become assumable. Correctness comes
    # entirely from the bounded retry in _create_hook_function on the InvalidParameterValueException
    # AWS raises for an unpropagated role, which already covers this delay with a real deadline.
    return resp["Role"]["Arn"]


def _create_hook_function(ctx, lam, exec_role_arn, hook_status, timeout_s=120):
    name = ctx.unique_name("sim2real-behav-cd-hook-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Handler="index.handler",
                Role=exec_role_arn,
                Code={"ZipFile": _make_zip(_HOOK_SRC)},
                MemorySize=128,
                Timeout=30,
                Environment={"Variables": {"HOOK_STATUS": hook_status}},
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            unpropagated = err.get("Code") == "InvalidParameterValueException" and (
                "role" in (err.get("Message") or "").lower())
            if unpropagated and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, name))
    _wait_lambda_active(lam, name)
    echoed = lam.get_function_configuration(FunctionName=name).get(
        "Environment", {}).get("Variables", {}).get("HOOK_STATUS")
    assert echoed == hook_status, (
        f"the hook function {name!r} reports HOOK_STATUS {echoed!r}, expected "
        f"{hook_status!r}; the one thing this check varies must be what it says it is"
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
