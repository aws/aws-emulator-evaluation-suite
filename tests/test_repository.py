"""The repository ships no bytecode, no dependency manifest under ``behavioral/``, only pinned
CI actions and hook repositories, and no security policy of its own."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _shipped() -> list[Path]:
    """The files a commit of this tree ships: git's view, else a walk outside ``.gitignore``."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        files = [ROOT / line for line in out.splitlines()]
    except (OSError, subprocess.CalledProcessError):
        files = _walk_unignored()
    return [p for p in files if p.is_file()]


def _walk_unignored() -> list[Path]:
    """Every file under ``ROOT`` but ``.git`` and what ``.gitignore`` names, for a tree without
    git: these tests hold an exported copy too."""
    patterns = [
        line.strip().rstrip("/")
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return [
        p
        for p in ROOT.rglob("*")
        if ".git" not in p.relative_to(ROOT).parts
        and not any(part.match(pat) for part in _parts(p) for pat in patterns)
    ]


def _parts(path: Path) -> list[Path]:
    rel = path.relative_to(ROOT)
    return [Path(part) for part in rel.parts]


def test_no_bytecode_or_caches_are_shipped():
    assert not [p for p in _shipped() if p.suffix == ".pyc" or "__pycache__" in p.parts]


#: File names GitHub's dependency graph reads as dependency manifests or lock files.
_MANIFEST = re.compile(
    r"(?i)(?:[^/]*requirements[^/]*\.(?:txt|in)|pipfile(?:\.lock)?|pyproject\.toml|setup\.py|"
    r"setup\.cfg|poetry\.lock|uv\.lock|package(?:-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|"
    r"pnpm-lock\.yaml|go\.(?:mod|sum)|pom\.xml|build\.gradle(?:\.kts)?|gradle\.lockfile|"
    r"gemfile(?:\.lock)?|[^/]*\.gemspec|cargo\.(?:toml|lock)|composer\.(?:json|lock)|"
    r"[^/]*\.(?:cs|vb|fs)proj|packages\.config|package\.swift|package\.resolved|pubspec\.(?:yaml|lock)|"
    r"mix\.(?:exs|lock))"
)


def test_the_fidelity_checks_ship_no_dependency_manifest():
    """The fidelity checks and their deployments run in the runner's environment, which
    ``uv.lock`` pins; a manifest under ``behavioral/`` is never installed from, yet the
    dependency graph raises alerts on it."""
    hits = [
        str(p.relative_to(ROOT))
        for p in _shipped()
        if p.relative_to(ROOT).parts[0] == "behavioral" and _MANIFEST.fullmatch(p.name)
    ]
    assert not hits, "\n".join(hits[:50])


#: A full commit SHA, the only immutable reference to an action or a hook repository.
_SHA = re.compile(r"[0-9a-f]{40}")


def test_every_ci_action_and_hook_repository_is_pinned_to_a_commit_sha():
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    uses = [
        (path.name, m.group(1))
        for path in workflows
        for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", path.read_text(), re.MULTILINE)
    ]
    hooks = re.findall(r"^\s*rev:\s*(\S+)", (ROOT / ".pre-commit-config.yaml").read_text(), re.M)
    assert uses and hooks
    unpinned = [
        f"{name}: {ref}" for name, ref in uses if not _SHA.fullmatch(ref.rpartition("@")[2])
    ]
    unpinned += [f".pre-commit-config.yaml: {rev}" for rev in hooks if not _SHA.fullmatch(rev)]
    assert not unpinned, unpinned


def test_the_repository_carries_no_security_policy_of_its_own():
    """The organization's security policy applies; a repository-level one would override it."""
    assert not [
        p for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md") if (ROOT / p).exists()
    ]
