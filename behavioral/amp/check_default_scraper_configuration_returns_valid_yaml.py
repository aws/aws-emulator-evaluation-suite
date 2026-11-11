"""default-scraper-configuration-returns-valid-yaml."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "default-scraper-configuration-returns-valid-yaml"
GROUP = "data-plane"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDefaultScraperConfiguration returns a non-trivial Prometheus scrape config blob that
    parses as YAML and declares at least one scrape_configs job."""
    amp = ctx.client("amp")
    raw = amp.get_default_scraper_configuration()["configuration"]
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8")
    else:
        text = raw

    parsed = _parse_yaml(text)
    assert isinstance(parsed, dict), f"default scraper configuration did not parse as a YAML mapping: {text[:200]!r}"
    assert "scrape_configs" in parsed, f"default scraper configuration has no scrape_configs: {parsed.keys()}"

    jobs = parsed["scrape_configs"]
    assert isinstance(jobs, list) and jobs, f"scrape_configs is not a non-empty list: {jobs!r}"
    # The template's job set is AWS-managed catalog data, so it is graded by shape only: every
    # job is a mapping with its own non-empty, unique job_name.
    job_names = [job.get("job_name") if isinstance(job, dict) else None for job in jobs]
    assert all(isinstance(n, str) and n for n in job_names), f"a scrape job has no job_name: {job_names}"
    assert len(set(job_names)) == len(job_names), f"duplicate job_name in scrape_configs: {job_names}"


def _parse_yaml(text):
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        pass

    # Minimal top-level-key scanner as a fallback when PyYAML isn't installed: good enough to
    # confirm the blob is YAML-shaped text with a scrape_configs section, not e.g. empty/JSON-only.
    result: dict = {}
    current_key = None
    current_list: list = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if not line.startswith((" ", "\t", "-")) and ":" in line:
            if current_key is not None:
                result[current_key] = current_list
            current_key = line.split(":", 1)[0].strip()
            current_list = []
        elif line.strip().startswith("-") and current_key is not None:
            current_list.append(line)
    if current_key is not None:
        result[current_key] = current_list
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
