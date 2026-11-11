"""alias-weight-ladder-observed-distribution."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "alias-weight-ladder-observed-distribution"
GROUP = 'versions_aliases'
SERVICES = ['lambda']

# --- the sample, and the bounds ----------------------------------------------------------- #
#
# N=200 per configuration, 8 concurrent invokers. The bounds below are the EXACT binomial
# quantiles at alpha = 1e-9 per tail, computed offline with
#
#   from math import comb
#   pm = [comb(N, k) * p**k * (1 - p)**(N - k) for k in range(N + 1)]
#   lo = smallest k with sum(pm[:k])   > alpha
#   hi = largest  k with sum(pm[k+1:]) > alpha
#
# and reproduced here so the numbers can be re-derived rather than trusted:
#
#   N=200 p=0.10 -> [1, 49]     P(k=0) = 7.06e-10
#   N=200 p=0.30 -> [24, 101]
#   N=200 p=0.50 -> [58, 142]
#
# The bands are deliberately loose: a one-in-a-billion-per-tail band over 200 draws cannot be
# tight, and a tight band would flake. THE DISCRIMINATION COMES FROM ORDERING ACROSS FOUR
# CONFIGURATIONS MEASURED IN THE SAME RUN, not from any single band -- see the ladder
# assertions. Nothing here asserts an exact split. The one exact assertion is the p=1.00 rung,
# which is not a split at all but a deterministic redirect (MEASURED 200/200, twice).
N = 200
WORKERS = 8
BAND_10 = (1, 49)
BAND_30 = (24, 101)
BAND_50 = (58, 142)
# Minimum separations between adjacent rungs. sigma is ~4.2 at p=0.10 and ~7.1 at p=0.50, so
# 20 is >2.4 sigma and 40 is >5 sigma from the null hypothesis that the rungs are drawn from
# the SAME distribution -- which is exactly the hypothesis a weight-blind dispatcher satisfies.
MIN_GAP_10_50 = 20
MIN_GAP_50_100 = 40
# The positive control's convergence probe, before the decisive sample.
POSCTRL_PROBE = 20

# --- why one alias PER RUNG, rather than one alias updated three times ------------------- #
#
# Observed on real Lambda:
#
#  * UpdateAlias's effect on the INVOKE path is not instantaneous across the invoke fleet. A
#    200-invoke sample started ~0.4 s after moving a live alias from 0.10 to 0.50 read k=29 --
#    i.e. ~85% of the sample was still dispatched under the OLD weight. Samples taken from
#    ~0.8 s onwards read 83..114 and stayed there for the 75 s the transition was watched, so
#    the tail is short; but "short" is a race, and a check that samples across a propagation
#    boundary is measuring a mixture of two distributions.
#  * A FRESHLY CREATED alias has no such boundary: there is no previously cached weight to be
#    stale. Measured, a brand-new weighted alias was fully consistent on its first sample --
#    p=0.10 -> 12/200 at 1.2 s after CreateAlias, p=0.50 -> 98/200 at 0.6 s, p=1.00 -> 200/200
#    at 0.6 s, p=0.30 -> 47/200 at 0.6 s. Every one is inside its band on the first read.
#
# So each rung gets its own alias, created once with its RoutingConfig, and no rung is ever
# mutated before it is measured. That removes the race instead of waiting it out, and it makes
# the check strictly STRONGER: the rungs coexist, so a target holding one global weight, or
# resolving the weight per FUNCTION rather than per ALIAS, now fails.
READY_TIMEOUT_S = 60

CODE = """\
def handler(event, context):
    return {"marker": "%s"}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Four coexisting alias weights (none, 0.10, 0.50, 1.00) yield strictly increasing canary
    shares, each consistent with its nominal weight (1.00 exactly); rejected weights (1.5, a
    missing version) change neither the stored config nor the traffic, vs a valid UpdateAlias."""
    lam = ctx.client("lambda")
    # ONE shared client with a widened connection pool, built here on the MAIN thread.
    # ctx.client caches per (service, endpoint, region, config, creds) behind a lock, so every
    # worker below is handed this same client; botocore clients are safe to CALL concurrently,
    # and the pool must be at least as wide as the worker count or the workers serialise on it
    # and the sample stops being concurrent.
    inv = ctx.client("lambda", config=Config(max_pool_connections=WORKERS + 4))

    fn = ctx.unique_name("sim2real-behav-fn-ladder-")
    _create_function(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_lambda_exec_role_arn(ctx), Code={"ZipFile": _make_zip(CODE % "v1")},
        MemorySize=128, Timeout=10,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _cleanup_function(ctx, lam, fn))
    _wait_lambda_active(lam, fn)

    v1 = lam.publish_version(FunctionName=fn, Description="sim2real-v1")["Version"]
    lam.update_function_code(FunctionName=fn, ZipFile=_make_zip(CODE % "v2"))
    _wait_lambda_active(lam, fn)
    v2 = lam.publish_version(FunctionName=fn, Description="sim2real-v2")["Version"]
    assert v1 != v2, f"PublishVersion must mint distinct versions, got {v1!r} and {v2!r}"
    marker_of = {v1: "v1", v2: "v2"}

    # --- the ladder, created all at once so the rungs coexist ---
    rungs = (("sim2real-rung-00", None), ("sim2real-rung-10", 0.10),
             ("sim2real-rung-50", 0.50), ("sim2real-rung-100", 1.00))
    for alias, p in rungs:
        _create_rung(ctx, lam, fn, alias, v1, v2, p)

    observed = {}
    for alias, p in rungs:
        _wait_alias_invokable(inv, fn, alias, READY_TIMEOUT_S)
        s = _sample(inv, fn, alias, N, marker_of)
        _assert_sample_healthy(s, f"{alias} (weight {p!r})", marker_of)
        k = s["counts"].get(v2, 0)
        observed[p] = k
        if p is None:
            assert k == 0, (
                f"{alias} carries no AdditionalVersionWeights, so every invoke must reach its "
                f"primary version {v1!r}; {k} of {N} reached {v2!r} instead "
                f"(counts={s['counts']!r}). A dispatcher that splits with no weight written "
                f"cannot be measured by the weighted rungs"
            )
        elif p >= 1.0:
            assert k == N, (
                f"{alias} weights {v2!r} at 1.0, so EVERY invoke must reach it; only {k} of "
                f"{N} did (counts={s['counts']!r}). This rung is deterministic on real AWS, so "
                f"a shortfall is a dispatcher that caps the weight or ignores it"
            )
            assert s["counts"].get(v1, 0) == 0, (
                f"{alias} weights {v2!r} at 1.0, so the primary {v1!r} must receive nothing; "
                f"it received {s['counts'].get(v1, 0)} of {N}"
            )
        else:
            _assert_band(k, BAND_10 if p == 0.10 else BAND_50, p, alias, s)
            # The complement, asserted independently, so a dispatcher that answers with a
            # THIRD thing cannot satisfy the check by making k alone look right.
            assert s["counts"].get(v1, 0) == N - k, (
                f"{alias}: the {N} invokes split {s['counts']!r}; every invoke must land on "
                f"exactly one of the two routed versions {sorted(marker_of)!r}, so the "
                f"primary's count must be {N - k}"
            )

    # --- the ladder assertion: the ORDERING is the discriminator ---
    k00, k10, k50, k100 = observed[None], observed[0.10], observed[0.50], observed[1.00]
    assert k00 < k10 < k50 < k100, (
        f"the observed canary share must INCREASE with the written weight: nominal "
        f"none/0.10/0.50/1.00 produced {k00}/{k10}/{k50}/{k100} out of {N}. A dispatcher whose "
        f"split is not parameterised by the stored weight -- a fixed interleave, a round-robin, "
        f"a hardcoded ratio, one weight shared across the function's aliases -- produces "
        f"statistically indistinguishable counts and fails here while passing every band"
    )
    assert k50 - k10 >= MIN_GAP_10_50, (
        f"the 0.10 -> 0.50 rung moved the observed count by only {k50 - k10} ({k10} -> {k50} "
        f"of {N}); a fivefold increase in the written weight must move it by at least "
        f"{MIN_GAP_10_50}"
    )
    assert k100 - k50 >= MIN_GAP_50_100, (
        f"the 0.50 -> 1.00 rung moved the observed count by only {k100 - k50} ({k50} -> {k100} "
        f"of {N}); it must move it by at least {MIN_GAP_50_100}"
    )

    # --- positive control for the negative arm below: UpdateAlias ITSELF, with a valid weight,
    # must succeed and take effect. Every rung above is weighted at CreateAlias; this is the only
    # place in the file that asks UpdateAlias to SET a weight rather than clear
    # or ignore one, so "1.5 is refused" cannot be mistaken for "every UpdateAlias weight write
    # is refused" ---
    posctrl = "sim2real-rung-posctrl"
    _create_rung(ctx, lam, fn, posctrl, v1, v2, None)
    _wait_alias_invokable(inv, fn, posctrl, READY_TIMEOUT_S)
    pc_updated = lam.update_alias(
        FunctionName=fn, Name=posctrl,
        RoutingConfig={"AdditionalVersionWeights": {v2: 0.50}})
    assert (pc_updated.get("RoutingConfig") or {}).get("AdditionalVersionWeights") == {v2: 0.50}, (
        f"a VALID UpdateAlias weight write must be accepted and echoed; {posctrl!r} echoed "
        f"{pc_updated.get('RoutingConfig')!r}, expected {{{v2!r}: 0.5}}"
    )
    pc_reread = (lam.get_alias(FunctionName=fn, Name=posctrl).get("RoutingConfig")
                 or {}).get("AdditionalVersionWeights") or {}
    assert pc_reread == {v2: 0.50}, (
        f"GetAlias after a valid UpdateAlias weight write reads AdditionalVersionWeights "
        f"{pc_reread!r} for {posctrl!r}, expected {{{v2!r}: 0.5}}"
    )
    # The data plane is eventual for a weight just SET, exactly as it is for one just cleared
    # (see the header comment on UpdateAlias's invoke-path lag). Poll a small probe to
    # convergence before trusting a decisive sample to it.
    pc_timeout = READY_TIMEOUT_S
    pc_probe = _poll(
        lambda: _sample(inv, fn, posctrl, POSCTRL_PROBE, marker_of),
        lambda s: not s["bad"] and s["counts"].get(v2, 0) >= 3,
        timeout_s=pc_timeout, interval_s=2)
    assert not pc_probe["bad"], (
        f"{posctrl} (positive control probe): {len(pc_probe['bad'])} of {len(pc_probe['rows'])} "
        f"invokes were not a clean matched 200. First three: {pc_probe['bad'][:3]!r}"
    )
    assert pc_probe["counts"].get(v2, 0) >= 3, (
        f"{pc_timeout}s after a VALID UpdateAlias set weight 0.50 on {posctrl!r}, a "
        f"{POSCTRL_PROBE}-invoke probe still shows {pc_probe['counts']!r}; UpdateAlias must be "
        f"able to SET a weight and have it take effect on the invoke path, not only clear one"
    )
    pc_final = _sample(inv, fn, posctrl, N, marker_of)
    _assert_sample_healthy(pc_final, f"{posctrl} (positive control, decisive)", marker_of)
    _assert_band(pc_final["counts"].get(v2, 0), BAND_50, 0.50, posctrl, pc_final)

    # --- negative arm 1: a weight above the documented maximum ---
    # MEASURED: ValidationException, "Member must have value less than or equal to".
    victim = "sim2real-rung-50"
    over_code, over_message = _error_code(lambda: lam.update_alias(
        FunctionName=fn, Name=victim,
        RoutingConfig={"AdditionalVersionWeights": {v2: 1.5}}))
    assert over_code == "ValidationException", (
        f"an AdditionalVersionWeights value of 1.5 must be refused ValidationException, got "
        f"{over_code!r}"
    )
    assert over_message == "1 validation error detected: Value '{2=1.5}' at 'routingConfig.additionalVersionWeights' failed to satisfy constraint: Map value must satisfy constraint: [Member must have value less than or equal to 1.0, Member must have value greater than or equal to 0.0, Member must not be null]", (
        f"expected the exact ValidationException message AWS returns, got {over_message!r}"
    )

    # --- negative arm 2: a weight naming a version that does not exist ---
    # MEASURED: ResourceNotFoundException, "Function not found: <arn>:9999".
    bogus_code, bogus_message = _error_code(lambda: lam.update_alias(
        FunctionName=fn, Name=victim,
        RoutingConfig={"AdditionalVersionWeights": {"9999": 0.30}}))
    assert bogus_code == "ResourceNotFoundException", (
        f"an AdditionalVersionWeights entry naming the nonexistent version '9999' must be "
        f"refused ResourceNotFoundException, got {bogus_code!r}"
    )
    assert bogus_message == f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}:9999", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {bogus_message!r}"
    )

    # --- the effect is absent on BOTH planes ---
    still = (lam.get_alias(FunctionName=fn, Name=victim).get("RoutingConfig")
             or {}).get("AdditionalVersionWeights") or {}
    assert still == {v2: 0.50}, (
        f"effect not absent on the control plane: after two refused writes {victim!r} reads "
        f"AdditionalVersionWeights {still!r}, expected {{{v2!r}: 0.5}}"
    )
    after = _sample(inv, fn, victim, N, marker_of)
    _assert_sample_healthy(after, f"{victim} after two refused writes", marker_of)
    k50_after = after["counts"].get(v2, 0)
    _assert_band(k50_after, BAND_50, 0.50, f"{victim} after two refused writes", after)

    # --- the control, in the same file: a valid weight is still accepted AND observed ---
    # Without this, a target that refuses everything passes both negatives above.
    control = "sim2real-rung-30"
    _create_rung(ctx, lam, fn, control, v1, v2, 0.30)
    _wait_alias_invokable(inv, fn, control, READY_TIMEOUT_S)
    ctrl = _sample(inv, fn, control, N, marker_of)
    _assert_sample_healthy(ctrl, f"{control} (control weight 0.30)", marker_of)
    k30 = ctrl["counts"].get(v2, 0)
    _assert_band(k30, BAND_30, 0.30, control, ctrl)
    assert k10 < k30 < k50, (
        f"control: the 0.30 rung created after two refused writes must sit between the 0.10 "
        f"and 0.50 rungs measured by the same sampler: 0.10 -> {k10}, 0.30 -> {k30}, "
        f"0.50 -> {k50} out of {N}"
    )


# ===== helpers =====

def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _error_code(fn):
    """The raised ClientError's code and message. Raises if the call unexpectedly SUCCEEDS, so an
    over-permissive target can never pass as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        "the call was expected to be refused but it SUCCEEDED; an accepted call is a "
        "stronger signal than a wrong error code and must not read as one"
    )


def _create_rung(ctx, lam, fn, alias, v1, v2, p):
    """One alias of the ladder, created with its weight, cleanup registered immediately, and
    the stored weight read back before anything is measured through it -- so an observed
    distribution can never be blamed on a write that did not land."""
    kwargs = {"FunctionName": fn, "Name": alias, "FunctionVersion": v1}
    if p is not None:
        kwargs["RoutingConfig"] = {"AdditionalVersionWeights": {v2: p}}
    created = lam.create_alias(**kwargs)
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn, Name=alias))
    want = {} if p is None else {v2: p}
    echoed = (created.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
    assert echoed == want, (
        f"CreateAlias for {alias!r} echoed AdditionalVersionWeights {echoed!r}, expected "
        f"{want!r}"
    )
    reread = (lam.get_alias(FunctionName=fn, Name=alias).get("RoutingConfig")
              or {}).get("AdditionalVersionWeights") or {}
    assert reread == want, (
        f"GetAlias reads AdditionalVersionWeights {reread!r} for {alias!r}, expected {want!r}"
    )
    assert lam.get_alias(FunctionName=fn, Name=alias)["FunctionVersion"] == v1, (
        f"{alias!r} must have primary version {v1!r}"
    )


def _wait_alias_invokable(inv, fn, alias, timeout_s):
    """Poll until the alias answers an invoke at all. An observable readiness condition, not a
    convergence wait: MEASURED, a freshly created weighted alias is already distributionally
    correct on its first sample, so there is nothing to converge to -- what this bounds is a
    brand-new alias not yet being resolvable, which surfaces as a ClientError."""
    ok = _poll(lambda: _invoke_once(inv, fn, alias, {}),
               lambda row: row[0] is not None, timeout_s=timeout_s, interval_s=1)
    assert ok[0] is not None, (
        f"{fn}:{alias} did not answer an invoke within {timeout_s}s; the last attempt "
        f"reported {ok[2]!r}"
    )


def _invoke_once(inv, fn, alias, marker_of):
    """One alias invoke, reduced to what the assertions need.

    The tuple carries both halves of the version claim: the version the service SAYS ran
    (ExecutedVersion) and the marker returned by the code that actually ran. A target that
    synthesises the label without dispatching differently is caught by their disagreement,
    which no count over ExecutedVersion alone could see. ``marker_of`` empty means "do not
    grade the pairing" -- used only by the readiness poll.
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
    if not marker_of:
        return (executed, marker, None)
    if executed not in marker_of:
        return (executed, marker, f"ExecutedVersion {executed!r} is not a routed version")
    if marker != marker_of[executed]:
        return (executed, marker,
                f"ExecutedVersion {executed!r} but the code returned marker {marker!r}")
    return (executed, marker, None)


def _sample(inv, fn, alias, n, marker_of, workers=WORKERS):
    """n concurrent alias invokes, tallied by the version that actually ran."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(lambda _: _invoke_once(inv, fn, alias, marker_of), range(n)))
    counts = {}
    for executed, _marker, _bad in rows:
        counts[executed] = counts.get(executed, 0) + 1
    return {"rows": rows, "counts": counts, "bad": [r for r in rows if r[2] is not None]}


def _assert_sample_healthy(s, label, marker_of):
    """Zero-error and zero-mismatch over the whole sample. The second half of every assertion
    pair here: a target that "splits" traffic by dropping requests, or by labelling responses
    with a version it did not run, fails here rather than in a count."""
    assert not s["bad"], (
        f"{label}: {len(s['bad'])} of {len(s['rows'])} invokes were not a clean 200 whose "
        f"returned marker matched its ExecutedVersion. First three: {s['bad'][:3]!r}"
    )
    unexpected = set(s["counts"]) - set(marker_of)
    assert not unexpected, (
        f"{label}: invokes reported ExecutedVersion(s) {sorted(unexpected)!r}, which are not "
        f"among the routed versions {sorted(marker_of)!r}; counts {s['counts']!r}"
    )


def _assert_band(k, band, p, label, s):
    lo, hi = band
    assert lo <= k <= hi, (
        f"{label}: at a nominal canary share of {p!r} over N={len(s['rows'])} invokes, {k} "
        f"reached the weighted version; the exact binomial band at alpha=1e-9 per tail is "
        f"[{lo}, {hi}]. Observed counts {s['counts']!r}"
    )


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

    Lambda creates the group some time after the first invocation, and CloudWatch Logs recreates
    a deleted group when a late batch of events arrives; so this waits up to ``appear_s`` for the
    group, then repeats the delete until it has stayed absent for ``quiet_s``.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
