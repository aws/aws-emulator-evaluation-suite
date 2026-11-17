"""cdk-machine-image-lookup-rejected-when-no-ami-matches-the-filter."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "cdk-machine-image-lookup-rejected-when-no-ami-matches-the-filter"
GROUP = "cdk-context-provider"
SERVICES = ["ec2"]

_SYNTH_TIMEOUT_S = 180.0
_APP = Path(__file__).parent / "deployments" / "cdk-machine-image-lookup"
_REAL_PATTERN = "al2023-ami-*-x86_64"


#: The filters the app passes to MachineImage.lookup besides its name pattern.
_APP_FILTERS = {"state": ["available"], "virtualization-type": ["hvm"]}
_STABLE_ATTEMPTS = 3


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c5",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """MachineImage.lookup(owners, filters) resolves to the most recently created AMI
    DescribeImages returns for the owners and filters CDK sends; when the name filter matches
    none, `cdk synth` exits non-zero with the provider's exact error line."""
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    acct = ctx.account

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check synthesizes is missing from disk: expected app.py and cdk.json "
        f"under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    bogus_pattern = ctx.unique_name("sim2real-no-such-ami-") + "-*"

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkamil-")
    work = _stage(ctx, _APP)

    # Positive control first: the context key names the owners and filters CDK sent.
    rc, out = _synth(ctx, work, qualifier, stack, acct, _REAL_PATTERN)
    assert rc == 0, (
        f"the POSITIVE CONTROL failed: `cdk synth` with name filter {_REAL_PATTERN!r} exited "
        f"{rc}, expected 0. Output tail: {out[-800:]!r}"
    )
    key, _ = _ami_entry(work)
    owners, filters = _key_query(key)
    assert owners == ["amazon"], f"context key {key!r} names owners {owners!r}, expected ['amazon']"
    sent = {k: filters.get(k) for k in ("name", *_APP_FILTERS)}
    assert sent == {"name": [_REAL_PATTERN], **_APP_FILTERS}, (
        f"context key {key!r} names filters {filters!r}, expected the app's {sent!r} among them"
    )

    # The lookup equals the latest match of the same query, read before and after one synth
    # that saw no newer image published in between.
    for _attempt in range(_STABLE_ATTEMPTS):
        before = _latest_image(ec2, owners, filters)
        _clear_assembly(work)
        rc, out = _synth(ctx, work, qualifier, stack, acct, _REAL_PATTERN)
        assert rc == 0, f"control: `cdk synth` exited {rc}. Output tail: {out[-800:]!r}"
        after = _latest_image(ec2, owners, filters)
        if before == after:
            break
    else:
        raise AssertionError(
            f"the latest image for {filters!r} changed during each of {_STABLE_ATTEMPTS} synths"
        )
    key2, resolved = _ami_entry(work)
    assert (key2, resolved) == (key, after), (
        f"MachineImage.lookup resolved {key2!r} -> {resolved!r}, expected {key!r} -> the most "
        f"recently created match {after!r}"
    )
    template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    assert template["Outputs"]["ImageId"]["Value"] == after, (
        f"the control template's ImageId output is {template['Outputs']['ImageId']['Value']!r}, "
        f"expected the literal resolved id {after!r}"
    )

    # Negative: the name filter matches no AMI at all.
    _clear_assembly(work)
    rc2, out2 = _synth(ctx, work, qualifier, stack, acct, bogus_pattern)
    assert rc2 != 0, (
        f"`cdk synth` exited 0 with name filter {bogus_pattern!r}, which matches no AMI. "
        f"Output tail: {out2[-500:]!r}"
    )
    want_lines = [f"[Error at /{stack}] No AMI found that matched the search criteria"]
    got_lines = _error_lines(work, stack)
    assert got_lines == want_lines, (
        f"assembly error annotations for {bogus_pattern!r}: expected {want_lines!r}, got {got_lines!r}"
    )
    denied_templates = sorted((work / "cdk.out").glob("*.template.json"))
    assert len(denied_templates) == 1, (
        f"the refused arm wrote {len(denied_templates)} templates, expected exactly 1"
    )
    denied_doc = json.loads(denied_templates[0].read_text())
    assert denied_doc["Outputs"]["ImageId"]["Value"] == "ami-1234", (
        f"the refused arm's ImageId output is {denied_doc['Outputs']['ImageId']['Value']!r}, "
        f"expected the lookup's placeholder 'ami-1234'"
    )
    denied_context = json.loads((work / "cdk.context.json").read_text())
    assert [k for k in denied_context if k.startswith("ami:")] == [], (
        f"an ami: context entry was written for a lookup that matched nothing: "
        f"{sorted(denied_context)!r}"
    )


def _ami_entry(work: Path) -> tuple[str, str]:
    """The one ami: context key the synth wrote and its value."""
    context = json.loads((work / "cdk.context.json").read_text())
    ami_keys = [k for k in context if k.startswith("ami:")]
    assert len(ami_keys) == 1, f"cdk.context.json holds ami keys {ami_keys!r}, expected exactly 1"
    return ami_keys[0], context[ami_keys[0]]


def _key_query(key: str) -> tuple[list[str], dict[str, list[str]]]:
    """Owners and filters out of an ami: context key (``filters.<name>.<i>=<v>``, ``owners.<i>=<v>``)."""
    owners: dict[int, str] = {}
    filters: dict[str, dict[int, str]] = {}
    for part in key.split(":")[1:]:
        field, _, value = part.partition("=")
        bits = field.split(".")
        if bits[0] == "owners":
            owners[int(bits[1])] = value
        elif bits[0] == "filters":
            filters.setdefault(".".join(bits[1:-1]), {})[int(bits[-1])] = value
    return (
        [owners[i] for i in sorted(owners)],
        {k: [v[i] for i in sorted(v)] for k, v in filters.items()},
    )


def _latest_image(ec2, owners: list[str], filters: dict[str, list[str]]) -> str:
    """The most recently created image DescribeImages returns for the query."""
    images = (
        ec2.get_paginator("describe_images")
        .paginate(
            Owners=owners,
            Filters=[{"Name": k, "Values": v} for k, v in sorted(filters.items())],
        )
        .build_full_result()["Images"]
    )
    assert images, f"no image matches owners {owners!r} and filters {filters!r}"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _error_lines(work: Path, stack: str) -> list[str]:
    """The cloud assembly's error annotations for the stack's constructs, as ``[Error at <path>] <msg>``.

    Read from the assembly the synth wrote, not the CLI output, whose layout varies by CLI version.
    """
    out = work / "cdk.out"
    entries: dict[str, list] = dict(
        json.loads((out / "manifest.json").read_text())["artifacts"].get(stack, {}).get("metadata")
        or {}
    )
    side = out / f"{stack}.metadata.json"
    if side.is_file():
        entries.update(json.loads(side.read_text()))
    return [
        f"[Error at {path}] {e['data']}"
        for path, items in sorted(entries.items())
        for e in items
        if e.get("type") == "aws:cdk:error"
    ]


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and cdk.context.json stay out of the checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkamil-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _clear_assembly(work: Path) -> None:
    """Remove the cloud assembly and context cache so the next synth performs the lookup again."""
    shutil.rmtree(work / "cdk.out", ignore_errors=True)
    (work / "cdk.context.json").unlink(missing_ok=True)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _synth(
    ctx, work: Path, qualifier: str, stack: str, acct: str, name_pattern: str
) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["AMI_NAME_PATTERN"] = name_pattern
    cmd = [
        "cdk",
        "synth",
        "--quiet",
        "--ci",
        "--no-version-reporting",
        "--app",
        f"{sys.executable} app.py",
    ]
    timeout_s = _budget_s(ctx, _SYNTH_TIMEOUT_S)
    try:
        r = subprocess.run(
            cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s
        )
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError("`cdk synth`: the run budget ended first; not graded") from None
        raise AssertionError(f"`cdk synth` did not finish within {timeout_s}s") from None
    return r.returncode, _ANSI.sub("", r.stdout + r.stderr)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
