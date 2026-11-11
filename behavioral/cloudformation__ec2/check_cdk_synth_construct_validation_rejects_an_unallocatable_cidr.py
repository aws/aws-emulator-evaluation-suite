"""cdk-synth-construct-validation-rejects-an-unallocatable-cidr."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "cdk-synth-construct-validation-rejects-an-unallocatable-cidr"
GROUP = "deploy-cdk-l2-vpc"
SERVICES = ["cloudformation", "ec2"]

# Generous margin over a ~20 s synth.
_SYNTH_TIMEOUT_S = 420.0

_APP = Path(__file__).parent / "deployments" / "cdk-construct-validation"

# The valid twin differs from both negatives only in this value.
_VALID_CIDR = "10.71.0.0/16"
# /28 cannot hold one /24 subnet per AZ, so the construct's subnet allocator refuses.
_UNALLOCATABLE_CIDR = "10.71.0.0/28"
# Not an address at all: input validation, a different rejection class.
_MALFORMED_CIDR = "not-a-cidr"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk synth` refuses a VPC CIDR too small for its subnets and a malformed CIDR with distinct
    errors and no template; the valid twin synthesizes and passes CloudFormation ValidateTemplate.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_ec2/Vpc.html
    """
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check synthesizes is missing from disk: expected app.py and cdk.json "
        f"under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkcidr-")
    work = _stage(ctx, _APP)

    # Positive control first. Without credentials the AZ context lookup makes even this synth fail.
    _clear_assembly(work)
    rc, out = _synth(ctx, work, qualifier, stack, _VALID_CIDR)
    assert rc == 0, (
        f"the POSITIVE CONTROL failed: `cdk synth` with the valid CIDR {_VALID_CIDR!r} exited "
        f"{rc}, expected 0. Without a succeeding control this check cannot tell 'rejects an "
        f"unallocatable CIDR' from 'rejects every app'. Output tail: {out[-500:]!r}"
    )
    templates = _templates(work)
    assert len(templates) == 1, (
        f"the valid arm wrote {len(templates)} CloudFormation templates "
        f"({[p.name for p in templates]!r}), expected exactly one for stack {stack!r}"
    )
    doc = json.loads(templates[0].read_text())
    kinds = _resource_kinds(doc)

    assert kinds.get("AWS::EC2::VPC") == 1, (
        f"the valid arm's template declares {kinds.get('AWS::EC2::VPC', 0)} AWS::EC2::VPC "
        f"resources, expected exactly 1. Resource kinds: {kinds!r}"
    )
    assert kinds.get("AWS::EC2::Subnet") == 2, (
        f"the valid arm's template declares {kinds.get('AWS::EC2::Subnet', 0)} AWS::EC2::Subnet "
        f"resources; one PUBLIC SubnetConfiguration across max_azs=2 must produce exactly 2. "
        f"Resource kinds: {kinds!r}"
    )
    assert "AWS::EC2::NatGateway" not in kinds, (
        f"the valid arm's template declares {kinds.get('AWS::EC2::NatGateway')} NAT gateways; "
        f"nat_gateways=0 must produce none. Resource kinds: {kinds!r}"
    )
    vpc_cidrs = [v["Properties"]["CidrBlock"] for v in doc["Resources"].values()
                 if v["Type"] == "AWS::EC2::VPC"]
    assert vpc_cidrs == [_VALID_CIDR], (
        f"the valid arm's template pins VPC CidrBlock(s) {vpc_cidrs!r}, expected exactly "
        f"[{_VALID_CIDR!r}] - the value the app was given"
    )

    # Independent server-side read of the synthesized template.
    validated = cfn.validate_template(TemplateBody=json.dumps(doc))
    reported = sorted(p["ParameterKey"] for p in validated.get("Parameters", []))
    assert reported == ["BootstrapVersion"], (
        f"CloudFormation ValidateTemplate reported parameters {reported!r} for the synthesized "
        f"template, expected ['BootstrapVersion'] - the single parameter "
        f"DefaultStackSynthesizer emits. Template Parameters were {sorted(doc['Parameters'])!r}"
    )
    assert sorted(doc["Parameters"]) == reported, (
        f"the template declares parameters {sorted(doc['Parameters'])!r} but ValidateTemplate "
        f"reported {reported!r}; the service must report the parameters the template actually "
        f"declares"
    )

    # Negative A: the subnet allocator refuses. Clearing the assembly keeps the previous arm's
    # template from satisfying the no-template assertion.
    _clear_assembly(work)
    rc_a, out_a = _synth(ctx, work, qualifier, stack, _UNALLOCATABLE_CIDR)
    assert rc_a != 0, (
        f"`cdk synth` exited 0 with VPC_CIDR {_UNALLOCATABLE_CIDR!r}; a /28 holds 16 addresses "
        f"and the app asks for a /24 subnet per availability zone, so the construct's subnet "
        f"allocator must refuse. Output tail: {out_a[-500:]!r}"
    )
    assert "SubnetCountExceedsRemainingSpace" in out_a, (
        f"the refusal of {_UNALLOCATABLE_CIDR!r} did not name the "
        f"SubnetCountExceedsRemainingSpace error class; a generic parse failure would mean the "
        f"allocator never ran. Output tail: {out_a[-800:]!r}"
    )
    assert "exceeds remaining space" in out_a and _UNALLOCATABLE_CIDR in out_a, (
        f"the refusal of {_UNALLOCATABLE_CIDR!r} named neither 'exceeds remaining space' nor the "
        f"offending CIDR itself; the message must identify the arithmetic that failed. Output "
        f"tail: {out_a[-800:]!r}"
    )
    left_a = _templates(work)
    assert left_a == [], (
        f"effect-absent: the refused synth of {_UNALLOCATABLE_CIDR!r} still wrote templates "
        f"{[p.name for p in left_a]!r}; a construct-validation failure must produce no cloud "
        f"assembly template at all"
    )

    # Negative B: input validation.
    _clear_assembly(work)
    rc_b, out_b = _synth(ctx, work, qualifier, stack, _MALFORMED_CIDR)
    assert rc_b != 0, (
        f"`cdk synth` exited 0 with VPC_CIDR {_MALFORMED_CIDR!r}, which is not an IP address at "
        f"all. Output tail: {out_b[-500:]!r}"
    )
    assert "InvalidIpAddress" in out_b and _MALFORMED_CIDR in out_b, (
        f"the refusal of {_MALFORMED_CIDR!r} named neither 'InvalidIpAddress' nor the offending "
        f"value; output tail: {out_b[-800:]!r}"
    )
    # The two negatives must be distinguishable, not one generic error.
    assert "SubnetCountExceedsRemainingSpace" not in out_b, (
        f"the malformed-CIDR refusal reported SubnetCountExceedsRemainingSpace, the allocator's "
        f"error; {_MALFORMED_CIDR!r} must fail input validation before any allocation is "
        f"attempted. Output tail: {out_b[-800:]!r}"
    )
    assert "InvalidIpAddress" not in out_a, (
        f"the unallocatable-CIDR refusal reported InvalidIpAddress; {_UNALLOCATABLE_CIDR!r} is a "
        f"WELL-FORMED address that merely cannot hold the requested subnets, so it must reach the "
        f"allocator. Output tail: {out_a[-800:]!r}"
    )
    left_b = _templates(work)
    assert left_b == [], (
        f"effect-absent: the refused synth of {_MALFORMED_CIDR!r} still wrote templates "
        f"{[p.name for p in left_b]!r}; expected none"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and cdk.context.json stay out of the checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkcidr-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _clear_assembly(work: Path) -> None:
    """Remove the cloud assembly and the context cache between arms.

    A stale template would satisfy "no template was written"; clearing cdk.context.json also forces
    the availability-zones lookup to run again.
    """
    shutil.rmtree(work / "cdk.out", ignore_errors=True)
    (work / "cdk.context.json").unlink(missing_ok=True)


def _templates(work: Path) -> list[Path]:
    """Every CloudFormation template in the cloud assembly, or [] if there is no assembly.

    An absent and an empty assembly mean the same thing for the negative arms.
    """
    out = work / "cdk.out"
    return sorted(out.glob("*.template.json")) if out.is_dir() else []


def _resource_kinds(doc: dict[str, Any]) -> dict[str, int]:
    """Resource-type histogram of a synthesized template; a missing Resources key fails loudly."""
    kinds: dict[str, int] = {}
    for v in doc["Resources"].values():
        kinds[v["Type"]] = kinds.get(v["Type"], 0) + 1
    return kinds


def _synth(ctx, work: Path, qualifier: str, stack: str, cidr: str) -> tuple[int, str]:
    """Run `cdk synth` with VPC_CIDR set to `cidr`, returning (returncode, combined output).

    Returns the raw result because each arm expects a different exit code.
    """
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    env["VPC_CIDR"] = cidr
    # --app runs the app with the interpreter that has aws-cdk-lib importable.
    cmd = ["cdk", "synth", "--quiet", "--ci", "--no-version-reporting",
           "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                       timeout=_SYNTH_TIMEOUT_S)
    return r.returncode, r.stdout + r.stderr


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
