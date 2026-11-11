"""cdk-bootstrapped-sfn-etl-workflow-alarm-echoes-one-minute-period."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-bootstrapped-sfn-etl-workflow-alarm-echoes-one-minute-period"
GROUP = "iac-long-horizon"
SERVICES = ["cloudwatch", "glue", "lambda", "logs", "s3", "stepfunctions"]

_APP_DIR = Path(__file__).parent / "deployments" / "sfn_etl_cdk"
_RECORDS = 3


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A bootstrapped `cdk deploy` publishes two Lambda directory assets and a Step Functions
    execution curates S3 data into a Glue partition; logs, metric, alarm period as declared, IAM
    denial, drift, one-asset rebuild, destroy and toolkit-teardown legs follow.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    """
    legs = _Legs(ctx, total=12)
    bucket = _new_bucket(ctx, "data")
    prefix = _xname(ctx, "cdkstk")
    main_stack, broken_stack = f"{prefix}-main", f"{prefix}-broken"
    context = {
        "stack_prefix": prefix,
        "data_bucket": bucket,
        "glue_database": _xname(ctx, "gluedb"),
        "glue_table": _xname(ctx, "gluetbl"),
        "metric_namespace": f"sim2real/xsvc/{ctx.unique_name('')[:10]}",
        "min_records": "1",
        "stage": "alpha",
    }

    app = _cdk_prepare(ctx, _APP_DIR)
    legs.hard("bootstrap", lambda: _bootstrap_cdk(ctx, legs, app, context=context))
    dep = legs.hard(
        "deploy",
        lambda: _deploy_cdk_bootstrapped(
            ctx, legs, app, stack=main_stack, asm_name="asm1", context=context, timeout_s=1200.0
        ),
    )

    legs.step("assets", lambda: _assert_both_assets_published(ctx, dep))
    legs.step("wiring", lambda: _assert_pipeline_curates(ctx, legs, dep, stage="alpha"))
    legs.step("logs", lambda: _assert_execution_logged(ctx, legs, dep), requires=("wiring",))
    legs.step("metrics", lambda: _assert_metric_datapoint(ctx, legs, dep), requires=("logs",))
    legs.step("alarm", lambda: _assert_alarm_configured(ctx, dep["outputs"]))
    legs.step(
        "denial",
        lambda: _assert_broken_variant_denied(ctx, legs, app, dep, broken_stack, context),
        requires=("wiring",),
    )
    legs.step(
        "drift",
        lambda: _assert_definition_change_modifies(ctx, legs, app, dep, context),
        requires=("wiring",),
    )
    legs.step(
        "rebuild",
        lambda: _assert_one_asset_republished(ctx, legs, app, dep, context),
        requires=("drift",),
    )
    legs.step(
        "teardown",
        lambda: _assert_destroy_stops_delivery(ctx, legs, app, dep, broken_stack),
        requires=("wiring",),
    )
    # Not gated on `teardown`: attempting it unconditionally keeps the toolkit from leaking.
    legs.step("toolkit", lambda: _destroy_toolkit(ctx, legs, app))
    legs.verdict()
_EVIDENCE_CAP = 120
_HEADLINE_CAP = 280


def _one_line(text: str, cap: int = _EVIDENCE_CAP) -> str:
    """Collapse to a single line, so a leg's evidence cannot displace the summary as the last line."""
    flat = " ".join(str(text).split())
    return flat[:cap]


class _Legs:
    """One PASS / FAIL / BLOCKED verdict per workflow leg, raised once at the end.

    The summary is the last line of the message.
    """

    def __init__(self, ctx, total: int) -> None:
        self._ctx = ctx
        self._total = total
        self._rows: list[tuple[str, str, str]] = []
        #: Legs that FAILED. Drives the final raise.
        self._failed: set[str] = set()
        #: Legs that did not PASS (failed or blocked). Drives `requires` gating, separately from
        #: `_failed`, so a leg whose prerequisite was blocked is blocked too.
        self._not_passed: set[str] = set()

    def _record(self, name: str, verdict: str, evidence: str) -> None:
        self._rows.append((name, verdict, evidence))
        # Printed as it happens so a run killed by its budget still leaves a trail.
        print(f"[leg {len(self._rows)}/{self._total}] {verdict:7} {name}: {evidence}", flush=True)

    def step(self, name: str, fn, *, requires: tuple[str, ...] = ()):
        """Run leg *name*; record BLOCKED when a prerequisite did not pass.

        BLOCKED rather than FAIL keeps one broken hop from becoming a failure per downstream leg.
        """
        blocked_by = [r for r in requires if r in self._not_passed]
        if blocked_by:
            self._not_passed.add(name)
            self._record(name, "BLOCKED", f"requires {','.join(blocked_by)}")
            return None
        try:
            evidence = fn()
        # AssertionError is recorded, not re-raised (unlike `hard`): aborting on the first failing
        # leg would skip the in-band teardown legs and leak a stack the cleanup budget cannot delete.
        except BaseException as exc:  # noqa: BLE001 -- recorded, then re-raised in aggregate
            self._failed.add(name)
            self._not_passed.add(name)
            self._record(name, "FAIL", _one_line(exc))
            return None
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def hard(self, name: str, fn):
        """A leg with nothing gradeable downstream (deploy, bootstrap): raise immediately rather than
        reporting derived failures for a stack that never came up.
        """
        try:
            evidence = fn()
        except AssertionError:
            raise
        except BaseException as exc:  # noqa: BLE001
            self._record(name, "FAIL", _one_line(exc))
            raise AssertionError(self._summary(name, _one_line(exc))) from exc
        self._record(name, "PASS", _one_line(evidence if evidence is not None else "ok"))
        return evidence

    def never_reached(self, what: str, waited_s: float):
        """Fail for a state the target accepted and never reached."""
        raise AssertionError(f"{what}; not reached after {waited_s:.0f}s of polling")

    def _summary(self, headline_leg: str, headline_evidence: str) -> str:
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        cells = " ".join(f"{n}={v}" for n, v, _ in self._rows)
        # The cells are truncated, never the headline, which must survive intact.
        head = _one_line(f"WORKFLOW FAILED at {headline_leg}: {headline_evidence}", _HEADLINE_CAP)
        return f"LEGS {n_pass}/{self._total} PASS | {cells[:900]}\n{head}"

    def verdict(self) -> None:
        """Raise once if any leg failed. Call as the LAST statement of run()."""
        n_pass = sum(1 for _, v, _ in self._rows if v == "PASS")
        print(f"[legs] {n_pass}/{self._total} PASS", flush=True)
        if not self._failed:
            return
        leg, _, evidence = next(r for r in self._rows if r[1] == "FAIL")
        raise AssertionError(self._summary(leg, evidence))


# --- names, polling ----------------------------------------------------------
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe,
    predicate,
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
    description: str = "condition",
    legs: Any = None,
):
    """Poll until *predicate* holds, else report a non-convergence (never a timeout).

    With ``legs``, exhaustion goes through ``_Legs.never_reached``; without, it is a plain assertion.
    """
    started = time.monotonic()
    deadline = started + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    waited = time.monotonic() - started
    if legs is not None:
        legs.never_reached(f"{description} not observed (last={_one_line(last, 60)})", waited)
    raise AssertionError(f"{description} not observed in {timeout_s:.0f}s (last={_one_line(last, 90)})")


def _swallow(fn, *codes: str):
    """Call *fn*, treating the named ClientError codes as success (idempotent teardown)."""
    try:
        return fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in codes:
            return None
        raise


# --- the bootstrapped CDK deploy path ---------------------------------------
#
# The customer's shape: `cdk bootstrap` -> `cdk synth` -> `cdk deploy --require-approval never`
# (cdk-assets publishes every asset) -> read outputs through CloudFormation -> `cdk destroy --force`.
# The toolkit is minted per run (`--qualifier` plus `--toolkit-stack-name`) so every target takes
# the create path, no concurrent check shares its bucket and roles, and it can be destroyed. The
# qualifier must be short and alphanumeric; the toolkit stack name carries the `sim2real-` prefix.
_CDK_QUALIFIER_CONTEXT = "@aws-cdk/core:bootstrapQualifier"
_CDK_MIN_BOOTSTRAP_VERSION = 6


def _version_param(qualifier: str) -> str:
    """The SSM parameter `cdk deploy`'s CheckBootstrapVersion rule reads."""
    return f"/cdk-bootstrap/{qualifier}/version"
# --ci keeps the CLI off a TTY; --no-notices / --no-version-reporting keep it off the network for
# anything that is not the target (a notices fetch failure must never look like a target verdict).
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")
_STACK_HEALTHY = frozenset({"CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"})
_DESTROY_BUDGET_S = 1800.0


def _asset_bucket(qualifier: str, account: str, region: str) -> str:
    return f"cdk-{qualifier}-assets-{account}-{region}"


def _asset_repo(qualifier: str, account: str, region: str) -> str:
    return f"cdk-{qualifier}-container-assets-{account}-{region}"


def _stack_status(cfn, name: str) -> str | None:
    """The stack's status, or None when it does not exist (CloudFormation reports a ValidationError)."""
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code") or ""
        if code in {"ValidationError", "StackNotFoundException"} and "does not exist" in str(exc):
            return None
        if code == "StackNotFoundException":
            return None
        raise


def _stack_outputs(cfn, name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _sub_env(text: str, account: str, region: str) -> str:
    return text.replace("${AWS::AccountId}", account).replace("${AWS::Region}", region)


def _read_assets(asm: Path, stack: str, account: str, region: str) -> dict[str, list[dict]]:
    """The cloud assembly's own asset manifest for *stack*.

    `<stack>.assets.json` is what cdk-assets publishes from, so it names exactly the keys to expect and
    delete; `zip` assets are the app's directories, the `file` one is the staged template.
    """
    path = asm / f"{stack}.assets.json"
    doc = json.loads(path.read_text()) if path.exists() else {}
    files: list[dict] = []
    for digest, spec in (doc.get("files") or {}).items():
        source = spec.get("source") or {}
        for dest in (spec.get("destinations") or {}).values():
            files.append(
                {
                    "hash": digest,
                    # The assembly's own label ("Fn/Code", "Transform/Code", "<stack> Template") —
                    # the only thing that tells two zip assets apart, since both stage as
                    # `asset.<hash>` and the hash is exactly what a content change moves.
                    "display": spec.get("displayName", ""),
                    "packaging": source.get("packaging", ""),
                    "source": source.get("path", ""),
                    "bucket": _sub_env(dest.get("bucketName", ""), account, region),
                    "key": _sub_env(dest.get("objectKey", ""), account, region),
                }
            )
    images: list[dict] = []
    for digest, spec in (doc.get("dockerImages") or {}).items():
        source = spec.get("source") or {}
        for dest in (spec.get("destinations") or {}).values():
            images.append(
                {
                    "hash": digest,
                    "display": spec.get("displayName", ""),
                    "source": source.get("directory", ""),
                    "repo": _sub_env(dest.get("repositoryName", ""), account, region),
                    "tag": dest.get("imageTag", ""),
                }
            )
    return {"files": files, "images": images}


def _zip_assets(assets: dict[str, list[dict]]) -> list[dict]:
    """Only the app's OWN directory assets — the staged stack template is not one of them."""
    return [f for f in assets.get("files") or [] if f.get("packaging") == "zip"]


#: Assets cdk-assets stages for aws-cdk-lib itself (BucketDeployment handler and CLI layer, the
#: auto-delete-objects provider). A fixed set shared by every CDK app, so they are never purged.
_LIBRARY_ASSET_MARKERS = ("Custom::", "AwsCliLayer")


def _owned_assets(assets: dict[str, list[dict]], kind: str) -> list[dict]:
    """The *kind* ("files"/"images") assets this app owns, excluding aws-cdk-lib's own."""
    return [
        a
        for a in assets.get(kind) or []
        if not any(marker in (a.get("display") or "") for marker in _LIBRARY_ASSET_MARKERS)
    ]


def _asset_named(assets: dict[str, list[dict]], display: str) -> dict:
    """The one zip asset the assembly labelled *display* (e.g. "Transform/Code")."""
    matches = [f for f in _zip_assets(assets) if f.get("display") == display]
    assert len(matches) == 1, f"expected one {display!r} asset, assembly declares {len(matches)}"
    return matches[0]


def _run_cdk(legs, app: dict, argv: list[str], *, what: str, timeout_s: float):
    """Run the cdk CLI in the staged workdir. Returns the CompletedProcess; never raises on rc.

    A wall-clock overrun goes through ``legs.never_reached``, never the subprocess exception's text.
    """
    cmd = ["cdk", *argv, *_CDK_FLAGS]
    print(f"[cdk] {' '.join(cmd[:6])} ... (budget {timeout_s:.0f}s)", flush=True)
    try:
        return subprocess.run(
            cmd,
            cwd=str(app["work"]),
            env=app["env"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        legs.never_reached(f"{what} did not finish inside its wall-clock budget", timeout_s)
    except OSError as exc:  # the CLI vanished between the availability probe and here
        raise AssertionError(f"cdk CLI not runnable: {type(exc).__name__}") from None


def _cdk_failed(what: str, done) -> None:
    """Raise for a non-zero `cdk` rc, with the tail of its output."""
    tail = _one_line(f"{done.stderr or ''} {done.stdout or ''}", 300)
    raise AssertionError(f"{what} rc={done.returncode}: {tail}")


def _cdk_prepare(ctx, app_dir) -> dict:
    """Stage a private copy of the CDK app and the child environment it runs under."""
    require_tools("cdk")
    ctx.verify_account_safety()
    work = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdk-"))
    shutil.copytree(
        Path(app_dir),
        work,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("cdk.out", ".venv", "__pycache__", "node_modules"),
    )
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    account = ctx.client("sts").get_caller_identity()["Account"]
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_ACCOUNT"] = account
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DISABLE_VERSION_CHECK"] = "1"
    # A leading letter plus 8 of `unique_name`'s 12 hex chars: the CLI wants a short alphanumeric
    # qualifier that is unique per bootstrap stack.
    return {
        "work": work,
        "env": env,
        "account": account,
        "owned": {},
        "qualifier": "s" + ctx.unique_name("")[:8],
        "toolkit_stack": _xname(ctx, "cdktk"),
    }


def _bootstrap_argv(
    ctx, app: dict, stack: str, qualifier: str, context: dict[str, str] | None
) -> list[str]:
    """argv for `cdk bootstrap`, carrying the same context the synth gets.

    `cdk bootstrap` synthesizes the app, which cannot be constructed without its context.
    """
    argv = [
        "bootstrap",
        f"aws://{app['account']}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        stack,
        "--tags",
        f"{_MANAGED_TAG_KEY}=true",
    ]
    # The qualifier goes in as context too, exactly as _cdk_synth does it: the app's stacks resolve
    # their synthesizer from this key, so bootstrap and deploy must agree on it.
    for key, value in {_CDK_QUALIFIER_CONTEXT: qualifier, **(context or {})}.items():
        argv.extend(["--context", f"{key}={value}"])
    return argv


def _bootstrap_cdk(
    ctx, legs, app: dict, *, context: dict[str, str] | None = None,
    want_repo: bool = False,
) -> str:
    """Create this run's own CDK bootstrap environment and assert what `cdk deploy` will look for.

    The DescribeStacks preflight separates a target that is not listening from one that cannot bootstrap.
    """
    cfn = ctx.client("cloudformation")
    stack, qualifier = app["toolkit_stack"], app["qualifier"]
    status = _stack_status(cfn, stack)
    # Idempotent within a run, strict across runs: the flag is set on `app` only after this run's
    # own bootstrap completed, so a toolkit left by a different run still trips the assertion.
    if app.get("bootstrapped"):
        assert status in _STACK_HEALTHY, (
            f"{stack} was bootstrapped by this run but now reads {status!r}; the toolkit must be "
            f"healthy for the asset publish that follows"
        )
        return f"reused {stack} qualifier {qualifier} (bootstrapped earlier this run)"
    assert status is None, (
        f"{stack} already exists ({status}) — this name is minted per run, so a collision means "
        "the toolkit is being shared and the parity this qualifier buys is gone"
    )
    # Registered before the create so a partial failure still tears down; LIFO runs it after the app
    # stacks' cleanups, which need the toolkit's roles to delete.
    ctx.on_cleanup(lambda: _sweep_toolkit(ctx, app))
    done = _run_cdk(
        legs,
        app,
        _bootstrap_argv(ctx, app, stack, qualifier, context),
        what="cdk bootstrap",
        timeout_s=900.0,
    )
    if done.returncode != 0:
        _cdk_failed("cdk bootstrap", done)
    _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: s in _STACK_HEALTHY,
        timeout_s=600.0,
        interval_s=10.0,
        description=f"{stack} reaching CREATE_COMPLETE",
        legs=legs,
    )
    # Assert what `cdk deploy` will itself look for, rather than trusting the CLI's exit code: the
    # SSM version parameter (the CheckBootstrapVersion rule reads it) and the staging bucket.
    version = ctx.client("ssm").get_parameter(Name=_version_param(qualifier))["Parameter"]["Value"]
    assert int(version) >= _CDK_MIN_BOOTSTRAP_VERSION, (
        f"bootstrap version {version} predates the asset-publishing roles"
    )
    bucket = _asset_bucket(qualifier, app["account"], ctx.region)
    ctx.client("s3").head_bucket(Bucket=bucket)
    detail = f"created {stack} v{version} qualifier {qualifier}, bucket {bucket}"
    if want_repo:
        repo = _asset_repo(qualifier, app["account"], ctx.region)
        ctx.client("ecr").describe_repositories(repositoryNames=[repo])
        detail += f", repo {repo}"
    app["bootstrapped"] = True
    return detail


def _empty_asset_store(ctx, app: dict) -> str:
    """Empty the staging bucket and asset repository so the toolkit stack can be deleted.

    CloudFormation refuses a non-empty bucket and ECR a repository holding images; the bucket is versioned.
    """
    qualifier, account = app["qualifier"], app["account"]
    bucket, objects = _asset_bucket(qualifier, account, ctx.region), 0
    s3 = ctx.client("s3")
    # Versions and delete markers: the staging bucket is versioned, so a plain delete_object leaves
    # the payload addressable under a marker.
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in [*(page.get("Versions") or []), *(page.get("DeleteMarkers") or [])]:
                s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
                objects += 1
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucket", "404"}:
            raise
    repo, images = _asset_repo(qualifier, account, ctx.region), 0
    ecr = ctx.client("ecr")
    try:
        for page in ecr.get_paginator("list_images").paginate(repositoryName=repo):
            ids = page.get("imageIds") or []
            if ids:
                ecr.batch_delete_image(repositoryName=repo, imageIds=ids)
                images += len(ids)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise
    return f"{objects} object(s), {images} image(s)"


def _destroy_toolkit(ctx, legs, app: dict) -> str:
    """Delete this run's bootstrap environment and prove it is gone, as a graded leg: one stack delete
    does not fit in the 60s cleanup budget. Evidence is the SSM version parameter, which `cdk deploy`
    reads, since ParameterNotFound is unambiguous where a head_bucket 404 is not.
    """
    stack, qualifier = app["toolkit_stack"], app["qualifier"]
    cfn = ctx.client("cloudformation")
    if _stack_status(cfn, stack) is None:
        return f"{stack} already gone"
    emptied = _empty_asset_store(ctx, app)
    cfn.delete_stack(StackName=stack)
    _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: s in (None, "DELETE_COMPLETE"),
        timeout_s=900.0,
        interval_s=10.0,
        description=f"{stack} deletion",
        legs=legs,
    )
    left = _swallow(
        lambda: ctx.client("ssm").get_parameter(Name=_version_param(qualifier)),
        "ParameterNotFound",
    )
    assert left is None, (
        f"{stack} reports deleted but {_version_param(qualifier)} survives — `cdk deploy` would "
        "still read this environment as bootstrapped"
    )
    # The bootstrap template retains the staging bucket and asset repository on stack delete; they
    # are already empty, and NoSuchBucket/RepositoryNotFoundException means a target did not retain them.
    bucket = _asset_bucket(qualifier, app["account"], ctx.region)
    _swallow(lambda: ctx.client("s3").delete_bucket(Bucket=bucket), "NoSuchBucket")
    survives = _swallow(lambda: ctx.client("s3").head_bucket(Bucket=bucket), "404", "NoSuchBucket")
    assert survives is None, f"staging bucket {bucket} survives its own delete_bucket call"
    repo = _asset_repo(qualifier, app["account"], ctx.region)
    _swallow(
        lambda: ctx.client("ecr").delete_repository(repositoryName=repo),
        "RepositoryNotFoundException",
    )
    return f"{stack} deleted, {emptied} purged, staging bucket and asset repository removed"


def _sweep_toolkit(ctx, app: dict) -> None:
    """Cleanup net for the toolkit when the graded `toolkit` leg did not delete it: delete the stack,
    wait for it to be gone, then remove the staging bucket and asset repository it retains."""
    stack, qualifier = app["toolkit_stack"], app["qualifier"]
    cfn = ctx.client("cloudformation")
    if _stack_status(cfn, stack) is None:
        return
    _empty_asset_store(ctx, app)
    cfn.delete_stack(StackName=stack)
    final = _wait_stack_gone(ctx, stack, timeout_s=_TEARDOWN_WAIT_GONE_S)
    if final not in (None, "DELETE_COMPLETE"):
        raise RuntimeError(
            f"bootstrap toolkit {stack} is {final} after delete_stack: its staging bucket, asset "
            "repository and IAM roles remain in the account"
        )
    bucket = _asset_bucket(qualifier, app["account"], ctx.region)
    _swallow(lambda: ctx.client("s3").delete_bucket(Bucket=bucket), "NoSuchBucket")
    repo = _asset_repo(qualifier, app["account"], ctx.region)
    _swallow(
        lambda: ctx.client("ecr").delete_repository(repositoryName=repo),
        "RepositoryNotFoundException",
    )


def _cdk_synth(ctx, legs, app: dict, *, asm_name: str, context: dict[str, str]) -> Path:
    """`cdk synth` into a named assembly dir. A synth failure is this app's defect, never a target verdict."""
    asm = app["work"] / asm_name
    argv = ["synth", "--output", str(asm)]
    # The synthesizer reads the qualifier from context, so asset names and CheckBootstrapVersion
    # address this run's toolkit rather than the account-wide default.
    for key, value in {_CDK_QUALIFIER_CONTEXT: app["qualifier"], **context}.items():
        argv.extend(["--context", f"{key}={value}"])
    done = _run_cdk(legs, app, argv, what=f"cdk synth ({asm_name})", timeout_s=420.0)
    if done.returncode != 0:
        raise AssertionError(
            f"cdk synth failed (local app defect, not a target verdict): "
            f"{_one_line(done.stderr or done.stdout, 200)}"
        )
    return asm


def _cdk_deploy_stack(ctx, legs, app: dict, *, stack: str, asm: Path, timeout_s: float = 1800.0) -> dict:
    """`cdk deploy --require-approval never` for one stack of a pre-synthesized assembly.

    Teardown is registered before the deploy, so a deploy cut short still gets destroyed.
    """
    cfn = ctx.client("cloudformation")
    rec = app["owned"].setdefault(stack, {"gone": False, "assets": {"files": [], "images": []}})
    if not rec.get("registered"):
        rec["registered"] = True
        ctx.on_cleanup(lambda: _cdk_destroy(ctx, app, stack, raise_on_leak=True))
    rec["asm"] = asm
    published = _read_assets(asm, stack, app["account"], ctx.region)
    # Union across deploys: a redeploy from a new assembly publishes NEW keys and the old ones are
    # still ours to remove, so teardown has to know about both.
    for kind in ("files", "images"):
        known = {(a.get("key") or a.get("tag")) for a in rec["assets"][kind]}
        rec["assets"][kind].extend(
            a for a in published[kind] if (a.get("key") or a.get("tag")) not in known
        )
    done = _run_cdk(
        legs,
        app,
        [
            "deploy",
            "--app",
            str(asm),
            stack,
            "--require-approval",
            "never",
            "--tags",
            f"{_MANAGED_TAG_KEY}=true",
        ],
        what=f"cdk deploy {stack}",
        timeout_s=timeout_s,
    )
    if done.returncode != 0:
        _cdk_failed(f"cdk deploy {stack}", done)
    status = _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: s in _STACK_HEALTHY,
        timeout_s=600.0,
        interval_s=10.0,
        description=f"stack {stack} reaching a complete state",
        legs=legs,
    )
    outputs = _stack_outputs(cfn, stack)
    return {
        "stack": stack,
        "status": status,
        "outputs": outputs,
        "assets": published,
        "asm": asm,
        "record": rec,
    }


def _deploy_cdk_bootstrapped(
    ctx,
    legs,
    app: dict,
    *,
    stack: str,
    asm_name: str,
    context: dict[str, str],
    timeout_s: float = 1800.0,
    want_repo: bool = False,
) -> dict:
    """Bootstrap (idempotent), synthesize, deploy the named stack with cdk-assets publishing every
    asset, read outputs through CloudFormation, and register the destroy, as one call so a synth
    failure stays inside the deploy leg.
    """
    _bootstrap_cdk(ctx, legs, app, context=context, want_repo=want_repo)
    asm = _cdk_synth(ctx, legs, app, asm_name=asm_name, context=context)
    return _cdk_deploy_stack(ctx, legs, app, stack=stack, asm=asm, timeout_s=timeout_s)


def _delete_all_versions(s3, bucket: str, key: str) -> None:
    """Remove every version and delete marker of *key* in the versioned staging bucket."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=key):
        for entry in [*(page.get("Versions") or []), *(page.get("DeleteMarkers") or [])]:
            if entry["Key"] != key:
                continue
            s3.delete_object(Bucket=bucket, Key=key, VersionId=entry["VersionId"])


def _purge_assets(ctx, assets: dict[str, list[dict]]) -> None:
    """Delete exactly the objects and images this check published; raise when one survives.

    cdk-assets uploads out of band, so the assets are not stack resources and `cdk destroy` leaves them.
    """
    s3 = ctx.client("s3")
    msgs: list[str] = []
    for asset in _owned_assets(assets, "files"):
        bucket, key = asset.get("bucket"), asset.get("key")
        if not bucket or not key:
            continue
        try:
            try:
                s3.delete_object(Bucket=bucket, Key=key)
                _delete_all_versions(s3, bucket, key)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucket", "NoSuchKey"}:
                    raise
        except Exception as exc:  # noqa: BLE001 -- collected, raised after every asset is tried
            msgs.append(
                f"published file asset s3://{bucket}/{key} was not removed "
                f"({type(exc).__name__}: {_one_line(exc, 90)}) — it stays in the SHARED bootstrap "
                "staging bucket, which no name-prefix cleanup matches"
            )
    images = _owned_assets(assets, "images")
    ecr = ctx.client("ecr") if images else None
    for image in images:
        repo, tag = image.get("repo"), image.get("tag")
        if not repo or not tag:
            continue
        try:
            try:
                resp = ecr.batch_delete_image(repositoryName=repo, imageIds=[{"imageTag": tag}])
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
                    raise
                resp = {}
            failures = (resp or {}).get("failures") or []
            failures = [f for f in failures if f.get("failureCode") != "ImageNotFound"]
            if failures:
                raise AssertionError(_one_line(failures, 90))
        except Exception as exc:  # noqa: BLE001 -- collected, raised after every asset is tried
            msgs.append(
                f"published image asset {repo}:{tag} was not removed "
                f"({type(exc).__name__}: {_one_line(exc, 90)}) — the layers stay in the SHARED "
                "bootstrap asset repository and are billed as storage"
            )
    if msgs:
        raise RuntimeError("; ".join(msgs))


def _wait_stack_gone(ctx, stack: str, *, timeout_s: float = 900.0) -> str | None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    status: str | None = "UNKNOWN"
    while time.monotonic() < deadline:
        status = _stack_status(cfn, stack)
        if status is None or status in {"DELETE_COMPLETE", "DELETE_FAILED"}:
            return status
        time.sleep(5.0)
    return status


#: The graded "teardown" leg destroys in-band with the full budgets above; these two bound the
#: on_cleanup safety net (``raise_on_leak=True``) that only does real work when that leg was
#: blocked or failed, so together they must fit inside the suite's cleanup budget.
_TEARDOWN_DESTROY_BUDGET_S = 400.0
_TEARDOWN_WAIT_GONE_S = 200.0


def _cdk_destroy(ctx, app: dict, stack: str, *, raise_on_leak: bool = False) -> str:
    """`cdk destroy --force`, verify through CloudFormation that the stack is gone, then purge the assets.

    A leak fails the graded leg (AssertionError); with ``raise_on_leak=True`` (teardown) it raises RuntimeError.
    """
    rec = app["owned"].get(stack)
    if rec is None or rec.get("gone"):
        return f"{stack} already destroyed"
    asm = rec.get("asm")
    destroy_timeout = _TEARDOWN_DESTROY_BUDGET_S if raise_on_leak else _DESTROY_BUDGET_S
    try:
        done = subprocess.run(
            ["cdk", "destroy", "--app", str(asm), stack, "--force", *_CDK_FLAGS],
            cwd=str(app["work"]),
            env=app["env"],
            capture_output=True,
            text=True,
            timeout=destroy_timeout,
        )
        rc, tail = done.returncode, _one_line(done.stderr or done.stdout, 200)
    except subprocess.TimeoutExpired as exc:
        # Deliberately not interpolating the exception text.
        msg = (
            f"cdk destroy for stack {stack} did not finish inside "
            f"{destroy_timeout:.0f}s of wall clock — every resource the stack owns remains in "
            "the account, and so does everything it published"
        )
        raise (RuntimeError if raise_on_leak else AssertionError)(msg) from exc
    except OSError as exc:
        msg = (
            f"cdk destroy for stack {stack} could not be launched "
            f"({type(exc).__name__}) — the stack remains in the account"
        )
        raise (RuntimeError if raise_on_leak else AssertionError)(msg) from exc
    final = _wait_stack_gone(
        ctx, stack, timeout_s=_TEARDOWN_WAIT_GONE_S if raise_on_leak else 900.0
    )
    if final is not None and final != "DELETE_COMPLETE":
        msg = (
            f"stack {stack} is {final} after cdk destroy (rc={rc}) — its resources remain "
            f"in the account: {tail}"
        )
        raise (RuntimeError if raise_on_leak else AssertionError)(msg)
    rec["gone"] = True
    _purge_assets(ctx, rec.get("assets") or {})
    return f"{stack} deleted (rc={rc})"


def _log_lines(
    ctx, log_group: str, *, needle: str, timeout_s: float, legs, what: str, ready=bool
) -> list[str]:
    """The events in *log_group* containing *needle*, waited for until *ready* (default: at least one).

    Step Functions delivers one execution's log lines in several asynchronous batches, so a caller
    needing a later event must say so through *ready*.
    """
    logs = ctx.client("logs")

    def _probe():
        try:
            streams = logs.describe_log_streams(logGroupName=log_group, limit=5).get(
                "logStreams", []
            )
        except ClientError:
            return None
        if not streams:
            return None
        found = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{needle}"')
        return [e["message"] for e in found.get("events", [])] or None

    return _poll_until(
        _probe,
        lambda r: r is not None and ready(r),
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"{what} in log group {log_group}",
        legs=legs,
    )


def _metric_sum(ctx, namespace: str, name: str, *, minutes: int = 20) -> float:
    cw = ctx.client("cloudwatch")
    now = datetime.now(timezone.utc)
    stats = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=name,
        StartTime=now - timedelta(minutes=minutes),
        EndTime=now + timedelta(minutes=2),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(float(p["Sum"]) for p in stats.get("Datapoints", []))


#: The alarm the app declares on the metric-filter metric, as DescribeAlarms reports it: Sum over
#: one 60 s period, one evaluation period, breaching at >= 1, missing data left missing, and actions
#: enabled by default because the app does not set them.
_ALARM_DECLARED = {
    "Statistic": "Sum",
    "Period": 60,
    "EvaluationPeriods": 1,
    "Threshold": 1.0,
    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
    "TreatMissingData": "missing",
    "ActionsEnabled": True,
}


def _assert_alarm_configured(ctx, outputs: dict) -> str:
    """The deployed alarm watches the stack's metric-filter metric with the declared period,
    evaluation, threshold and missing-data treatment, exactly as DescribeAlarms echoes them."""
    alarm = outputs["AlarmName"]
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[alarm])["MetricAlarms"]
    assert len(alarms) == 1, f"DescribeAlarms for {alarm} returned {len(alarms)} alarm(s)"
    got = alarms[0]
    watched = (got.get("Namespace"), got.get("MetricName"), got.get("Dimensions", []))
    want = (outputs["MetricNamespace"], outputs["MetricName"], [])
    assert watched == want, f"alarm {alarm} watches {watched!r}, expected {want!r}"
    echoed = {key: got.get(key) for key in _ALARM_DECLARED}
    assert echoed == _ALARM_DECLARED, (
        f"alarm {alarm} reports {echoed!r}, expected the declared {_ALARM_DECLARED!r}"
    )
    return f"{alarm} Sum/60s x1 >= 1 on {want[0]}/{want[1]}, missing data missing"


# --- the data bucket OUTLIVES the stack -------------------------------------
# Created here rather than in the CDK app so the teardown leg can assert an ABSENCE at the
# destination: after `cdk destroy` the bucket is still there, a fresh raw object can still be
# uploaded, and nothing may curate it.


def _new_bucket(ctx, kind: str) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is S3's region-pinned default: CreateBucket there rejects an explicit
    # LocationConstraint, so the region literal names that one region, not an assumption.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": _MANAGED_TAG_KEY, "Value": "true"}]})
    ctx.on_cleanup(lambda: _drop_bucket(ctx, name))
    return name


def _purge_bucket(ctx, bucket: str) -> int:
    s3 = ctx.client("s3")
    removed = 0
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in [*(page.get("Versions") or []), *(page.get("DeleteMarkers") or [])]:
                s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
                removed += 1
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {"NoSuchBucket", "404"}:
            raise
    return removed


def _drop_bucket(ctx, bucket: str) -> None:
    _purge_bucket(ctx, bucket)
    _swallow(lambda: ctx.client("s3").delete_bucket(Bucket=bucket), "NoSuchBucket")


# --- leg helpers -------------------------------------------------------------


def _upload_batch(ctx, dep: dict, *, records: int) -> tuple[str, str]:
    """A raw JSON-lines object for one batch. Returns (batch, key)."""
    batch = "b" + ctx.unique_name("")[:10]
    key = dep["outputs"]["RawPrefix"] + batch + ".jsonl"
    body = "\n".join(
        json.dumps({"id": f"{batch}-{index}", "value": f"v{index}"}) for index in range(records)
    )
    ctx.client("s3").put_object(Bucket=dep["outputs"]["DataBucket"], Key=key, Body=body.encode())
    return batch, key


def _start(ctx, arn: str, dep: dict, batch: str, key: str) -> str:
    return ctx.client("stepfunctions").start_execution(
        stateMachineArn=arn,
        name=f"x{batch}",
        input=json.dumps({"bucket": dep["outputs"]["DataBucket"], "key": key, "batch": batch}),
    )["executionArn"]


def _await_execution(ctx, legs, execution_arn: str, *, timeout_s: float = 300.0) -> dict:
    # "stepfunctions", not "sfn": boto3 has no service named sfn.
    sfn = ctx.client("stepfunctions")
    return _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda r: r["status"] != "RUNNING",
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"execution {execution_arn.rsplit(':', 1)[-1]} leaving RUNNING",
        legs=legs,
    )


def _curated_key(dep: dict, batch: str) -> str:
    return f"{dep['outputs']['CuratedPrefix']}batch={batch}/part-0.json"


def _get_object(ctx, bucket: str, key: str) -> str | None:
    try:
        return ctx.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    except ClientError:
        return None


def _assert_both_assets_published(ctx, dep: dict) -> str:
    """Each handler directory was published as its OWN object, and the deployed template points at
    both of them."""
    extract = _asset_named(dep["assets"], "Extract/Code")
    transform = _asset_named(dep["assets"], "Transform/Code")
    assert extract["key"] != transform["key"], (
        "both functions were pointed at the same published object — the asset key is not addressing "
        "the directory's content"
    )
    sizes = {}
    for asset in (extract, transform):
        head = ctx.client("s3").head_object(Bucket=asset["bucket"], Key=asset["key"])
        assert head["ContentLength"] > 0, f"published asset {asset['key']} is empty"
        sizes[asset["display"]] = head["ContentLength"]

    template = ctx.client("cloudformation").get_template(
        StackName=dep["stack"], TemplateStage="Processed"
    )["TemplateBody"]
    body = template if isinstance(template, str) else json.dumps(template)
    for asset in (extract, transform):
        assert asset["key"] in body, (
            f"the deployed template does not reference {asset['display']}'s published key "
            f"{asset['key']} — that function's code is not the object cdk-assets uploaded"
        )
    return f"{sizes} in s3://{extract['bucket']}"


def _assert_pipeline_curates(ctx, legs, dep: dict, *, stage: str) -> str:
    """One execution: raw object -> manifest -> curated partition object -> Glue partition."""
    outputs = dep["outputs"]
    batch, key = _upload_batch(ctx, dep, records=_RECORDS)
    execution = _await_execution(ctx, legs, _start(ctx, outputs["StateMachineArn"], dep, batch, key))
    assert execution["status"] == "SUCCEEDED", (
        f"execution ended {execution['status']}: {_one_line(execution.get('cause') or '', 90)}"
    )
    result = json.loads(execution["output"])
    assert result["extract"]["count"] == _RECORDS, (
        f"the extract stage reported {result['extract']['count']} records, not {_RECORDS}"
    )
    # The version strings come from the vendored module, so they are the proof that each function is
    # running code the published asset carried rather than something the target substituted.
    assert result["extract"]["parser"] == "1.0.0", f"unexpected parser {result['extract']['parser']}"
    assert result["transform"]["transformer"] == "1.0.0", "unexpected transformer version"
    assert result["transform"]["stage"] == stage, (
        f"the curated rows carry stage {result['transform']['stage']!r}, deployed value is {stage!r}"
    )

    curated = _poll_until(
        lambda: _get_object(ctx, outputs["DataBucket"], _curated_key(dep, batch)),
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"curated object for batch {batch}",
        legs=legs,
    )
    rows = [json.loads(line) for line in curated.splitlines() if line.strip()]
    assert len(rows) == _RECORDS, f"curated object holds {len(rows)} rows, not {_RECORDS}"
    assert all(row["digest"].startswith("sim2real-records:1.0.0:") for row in rows), (
        f"the curated rows were not digested by the vendored module: {_one_line(rows[0], 90)}"
    )
    assert all(row["stage"] == stage for row in rows), "a curated row carries the wrong stage"

    glue = ctx.client("glue")
    table = glue.get_table(DatabaseName=outputs["DatabaseName"], Name=outputs["TableName"])["Table"]
    assert table["StorageDescriptor"]["Location"].endswith(outputs["CuratedPrefix"]), (
        f"the catalog table points at {table['StorageDescriptor']['Location']}"
    )
    partitions = _poll_until(
        lambda: [
            p
            for p in glue.get_partitions(
                DatabaseName=outputs["DatabaseName"], TableName=outputs["TableName"]
            ).get("Partitions", [])
            if p["Values"] == [batch]
        ],
        lambda r: bool(r),
        timeout_s=120.0,
        interval_s=5.0,
        description=f"Glue partition batch={batch}",
        legs=legs,
    )
    assert partitions[0]["StorageDescriptor"]["Location"].endswith(f"batch={batch}/"), (
        f"the partition's location is {partitions[0]['StorageDescriptor']['Location']}"
    )
    dep["last_batch"] = batch
    return f"batch {batch}: {len(rows)} rows curated, partition registered, stage {stage}"


def _assert_execution_logged(ctx, legs, dep: dict) -> str:
    """Both log surfaces: the state machine's own execution history in CloudWatch Logs, and the
    transform stage's structured line."""
    batch = dep["last_batch"]
    machine_events = _log_lines(
        ctx,
        dep["outputs"]["MachineLogGroupName"],
        needle=batch,
        timeout_s=300.0,
        legs=legs,
        what="the state machine's execution log reaching a LambdaFunctionSucceeded entry",
        # Wait for LambdaFunctionSucceeded, which lands after the early batch. A Task whose resource
        # is a Lambda function logs the LambdaFunction* family, not the generic Task* events.
        ready=lambda lines: any("LambdaFunctionSucceeded" in line for line in lines),
    )
    kinds = {json.loads(line).get("type") for line in machine_events if line.strip().startswith("{")}
    assert kinds, f"the machine log group holds no JSON events: {_one_line(machine_events[:1], 90)}"
    assert any("LambdaFunctionSucceeded" in (kind or "") for kind in kinds), (
        f"the execution log records no LambdaFunctionSucceeded entry; saw "
        f"{_one_line(sorted(k for k in kinds if k), 90)}"
    )

    curated_lines = _log_lines(
        ctx,
        dep["outputs"]["TransformLogGroupName"],
        needle="SIM2REAL_CURATED",
        timeout_s=240.0,
        legs=legs,
        what="the transform stage's structured line",
    )
    records = [json.loads(line) for line in curated_lines if line.strip().startswith("{")]
    assert records and records[0].get("rows"), (
        f"the structured line carries no row count: {_one_line(curated_lines[:1], 90)}"
    )
    return f"{len(kinds)} machine event type(s) incl LambdaFunctionSucceeded, {len(records)} curated line(s)"


def _assert_metric_datapoint(ctx, legs, dep: dict) -> str:
    namespace, name = dep["outputs"]["MetricNamespace"], dep["outputs"]["MetricName"]
    total = _poll_until(
        lambda: _metric_sum(ctx, namespace, name),
        lambda v: v >= 1.0,
        timeout_s=360.0,
        interval_s=20.0,
        description=f"metric-filter datapoint for {namespace}/{name}",
        legs=legs,
    )
    return f"{namespace}/{name} Sum={total}"


def _assert_broken_variant_denied(ctx, legs, app: dict, dep: dict, broken_stack: str, context: dict) -> str:
    """A role that may invoke the extract stage only: the execution is refused AT THE TRANSFORM HOP
    by name, the extract stage's manifest is still written, and nothing is curated."""
    outputs = dep["outputs"]
    broken = _cdk_deploy_stack(
        ctx,
        legs,
        app,
        stack=broken_stack,
        asm=_cdk_synth(
            ctx,
            legs,
            app,
            asm_name="asmbroken",
            context=dict(
                context,
                extract_arn=outputs["ExtractFunctionArn"],
                transform_arn=outputs["TransformFunctionArn"],
            ),
        ),
        timeout_s=900.0,
    )
    batch, key = _upload_batch(ctx, dep, records=_RECORDS)
    execution = _await_execution(
        ctx, legs, _start(ctx, broken["outputs"]["BrokenStateMachineArn"], dep, batch, key)
    )
    assert execution["status"] == "FAILED", (
        f"the unauthorized execution ended {execution['status']}, not FAILED"
    )
    cause = f"{execution.get('error', '')} {execution.get('cause', '')}"
    if "not authorized" not in cause:
        history = ctx.client("stepfunctions").get_execution_history(
            executionArn=execution["executionArn"], reverseOrder=True, maxResults=20
        )
        cause += " " + json.dumps(history.get("events", []))
    assert "not authorized" in cause, f"failed, but not on authorization: {_one_line(cause, 130)}"
    assert "lambda:InvokeFunction" in cause, (
        f"the denial does not name the action that was withheld: {_one_line(cause, 130)}"
    )

    # The extract hop DID run: its manifest is in the bucket. That is what makes the denial
    # attributable to the transform hop rather than to the whole execution being unable to start.
    manifest = _poll_until(
        lambda: _get_object(ctx, outputs["DataBucket"], f"manifests/{batch}.json"),
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"the extract stage's manifest for batch {batch}",
        legs=legs,
    )
    manifest_batch = json.loads(manifest)["batch"]
    assert manifest_batch == batch, f"the manifest carries batch {manifest_batch!r}, not {batch!r}"
    assert _get_object(ctx, outputs["DataBucket"], _curated_key(dep, batch)) is None, (
        "the transform hop was refused AND the curated object was written anyway"
    )
    glue = ctx.client("glue")
    denied_partition = [
        p
        for p in glue.get_partitions(
            DatabaseName=outputs["DatabaseName"], TableName=outputs["TableName"]
        ).get("Partitions", [])
        if p["Values"] == [batch]
    ]
    assert not denied_partition, "no curated object, yet the Glue partition was registered"
    return (
        f"batch {batch}: InvokeFunction denied at the transform hop, manifest present, "
        f"curated object and partition absent"
    )


def _thresholds(node) -> list:
    """Every NumericGreaterThanEquals value in an ASL document, wherever the Choice sits.

    Read out of the deployed definition rather than matched as a substring: the service is free to
    re-serialize the JSON it was given, and a whitespace difference is not a behaviour difference.
    """
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "NumericGreaterThanEquals":
                found.append(value)
            else:
                found.extend(_thresholds(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_thresholds(item))
    return found


def _assert_definition_change_modifies(ctx, legs, app: dict, dep: dict, context: dict) -> str:
    """A second deploy that changes the state machine's DEFINITION and the transform stage's
    environment: modified not replaced, neither asset re-published, and the new threshold really
    decides the branch."""
    sfn = ctx.client("stepfunctions")
    outputs = dep["outputs"]
    before = sfn.describe_state_machine(stateMachineArn=outputs["StateMachineArn"])
    assets_before = {a["display"]: a for a in _zip_assets(dep["assets"])}
    heads_before = {
        display: ctx.client("s3").head_object(Bucket=a["bucket"], Key=a["key"])["LastModified"]
        for display, a in assets_before.items()
    }

    updated = dict(context, min_records="3", stage="beta")
    again = _deploy_cdk_bootstrapped(
        ctx, legs, app, stack=dep["stack"], asm_name="asm2", context=updated, timeout_s=1200.0
    )
    assert again["status"] == "UPDATE_COMPLETE", (
        f"the second deploy left the stack in {again['status']}, not UPDATE_COMPLETE"
    )
    after = sfn.describe_state_machine(stateMachineArn=outputs["StateMachineArn"])
    assert after["stateMachineArn"] == before["stateMachineArn"], (
        "the state machine was REPLACED by a definition change"
    )
    assert after["definition"] != before["definition"], "the definition change never landed"
    assert 3 in _thresholds(json.loads(after["definition"])), (
        f"the deployed definition does not carry the new threshold: {_one_line(after['definition'], 120)}"
    )
    env = ctx.client("lambda").get_function_configuration(
        FunctionName=outputs["TransformFunctionName"]
    )["Environment"]["Variables"]
    assert env["STAGE"] == "beta", f"the transform stage still runs with STAGE={env.get('STAGE')!r}"

    for display, asset in assets_before.items():
        now = _asset_named(again["assets"], display)
        assert now["key"] == asset["key"], (
            f"{display}'s asset key moved without its content changing "
            f"({asset['key'][:10]}… -> {now['key'][:10]}…)"
        )
        head = ctx.client("s3").head_object(Bucket=now["bucket"], Key=now["key"])
        assert head["LastModified"] == heads_before[display], (
            f"cdk-assets re-uploaded {display} although its content hash was unchanged"
        )

    dep["assets"] = again["assets"]
    dep["asm"] = again["asm"]
    context.update(updated)
    _assert_pipeline_curates(ctx, legs, dep, stage="beta")
    # And the new threshold is not merely present in the definition: a batch below it now fails on
    # the branch the deploy changed.
    small_batch, small_key = _upload_batch(ctx, dep, records=1)
    small = _await_execution(
        ctx, legs, _start(ctx, outputs["StateMachineArn"], dep, small_batch, small_key)
    )
    assert small["status"] == "FAILED" and small.get("error") == "EmptyBatch", (
        f"a 1-record batch ended {small['status']}/{small.get('error')} under a threshold of 3"
    )
    assert _get_object(ctx, outputs["DataBucket"], _curated_key(dep, small_batch)) is None, (
        "the Choice took the failing branch and something curated the batch anyway"
    )
    return "definition updated in place, no asset re-published, threshold 3 decides the branch"


def _assert_one_asset_republished(ctx, legs, app: dict, dep: dict, context: dict) -> str:
    """Change ONE asset's content: that asset must be published under a new key and the other must
    not move at all."""
    vendored = app["work"] / "transform" / "vendor" / "sim2real_records.py"
    vendored.write_text(vendored.read_text().replace('VERSION = "1.0.0"', 'VERSION = "2.0.0"'))
    extract_before = _asset_named(dep["assets"], "Extract/Code")
    transform_before = _asset_named(dep["assets"], "Transform/Code")

    again = _deploy_cdk_bootstrapped(
        ctx, legs, app, stack=dep["stack"], asm_name="asm3", context=context, timeout_s=1200.0
    )
    extract_after = _asset_named(again["assets"], "Extract/Code")
    transform_after = _asset_named(again["assets"], "Transform/Code")
    assert transform_after["key"] != transform_before["key"], (
        "the transform asset's content changed and its key did not — cdk-assets would keep serving "
        "the old zip"
    )
    assert extract_after["key"] == extract_before["key"], (
        "an unrelated asset's key moved: the publish is not addressing each directory's own content"
    )
    ctx.client("s3").head_object(Bucket=transform_after["bucket"], Key=transform_after["key"])

    dep["assets"] = again["assets"]
    dep["asm"] = again["asm"]
    batch, key = _upload_batch(ctx, dep, records=_RECORDS)
    execution = _await_execution(ctx, legs, _start(ctx, dep["outputs"]["StateMachineArn"], dep, batch, key))
    assert execution["status"] == "SUCCEEDED", f"post-rebuild execution ended {execution['status']}"
    result = json.loads(execution["output"])
    assert result["transform"]["transformer"] == "2.0.0", (
        f"the transform stage still runs transformer {result['transform']['transformer']} — the "
        "republished asset is not what it loaded"
    )
    assert result["extract"]["parser"] == "1.0.0", "the extract stage's code changed too"
    return f"transform republished as {transform_after['key'][:12]}…, extract untouched"


def _assert_destroy_stops_delivery(ctx, legs, app: dict, dep: dict, broken_stack: str) -> str:
    """After destroy: the state machine and the catalog are gone, a fresh raw object is not curated
    in the SURVIVING bucket, and the published assets are out of the shared staging bucket."""
    outputs = dep["outputs"]
    assets = list(dep["record"]["assets"]["files"])
    broken_result = _cdk_destroy(ctx, app, broken_stack)
    main_result = _cdk_destroy(ctx, app, dep["stack"])
    cfn = ctx.client("cloudformation")
    for stack in (broken_stack, dep["stack"]):
        status = _stack_status(cfn, stack)
        assert status in (None, "DELETE_COMPLETE"), f"stack {stack} is {status} after destroy"

    gone = _swallow(
        lambda: ctx.client("stepfunctions").describe_state_machine(
            stateMachineArn=outputs["StateMachineArn"]
        ),
        "StateMachineDoesNotExist",
        "ValidationException",
    )
    assert gone is None, "the state machine still exists after the stack was deleted"
    catalog = _swallow(
        lambda: ctx.client("glue").get_table(
            DatabaseName=outputs["DatabaseName"], Name=outputs["TableName"]
        ),
        "EntityNotFoundException",
    )
    assert catalog is None, "the Glue table outlived its stack"

    batch, _key = _upload_batch(ctx, dep, records=_RECORDS)
    # Sampled over a window rather than once: a delayed appearance (an earlier unawaited execution,
    # or a delete that left a worker running) must be caught during the window, not only at its edge.
    deadline = time.monotonic() + 45.0
    samples = 0
    while time.monotonic() < deadline:
        assert _get_object(ctx, outputs["DataBucket"], _curated_key(dep, batch)) is None, (
            "the pipeline still DELIVERS after the stack was destroyed — a raw object dropped on the "
            "surviving bucket produced a curated object"
        )
        samples += 1
        time.sleep(5.0)
    assert samples >= 3, f"the absence window took too few samples to be meaningful: {samples}"

    surviving = []
    for asset in assets:
        try:
            ctx.client("s3").head_object(Bucket=asset["bucket"], Key=asset["key"])
            surviving.append(asset["key"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("404", "NoSuchKey", "NoSuchBucket"):
                raise
    assert not surviving, (
        "teardown left published assets in the SHARED bootstrap staging bucket, which no name-prefix "
        f"cleanup matches: {_one_line(surviving, 90)}"
    )
    return f"{broken_result}; {main_result}; batch {batch} uncurated; {len(assets)} asset(s) purged"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
