## Description

<!-- What does this PR do? Why? -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update
- [ ] Research contribution (dataset, experiment, benchmark)
- [ ] Refactor (no functional change, improves code quality)

## Research Value

> Every change to SecuraX must increase engineering quality or scientific value.
> If neither, the PR should not be opened.

Which research question (from `docs/RESEARCH_ROADMAP.md`) or engineering principle
does this PR advance?

---

## Testing Evidence

```
# Paste test run output here
pytest tests/ -v -m "not benchmark"
```

- [ ] Tests pass locally with `--cov-fail-under=60`
- [ ] New code is covered by tests
- [ ] Benchmark run if risk engine was modified (`pytest -m benchmark`)

## Security Checklist

- [ ] No API keys, passwords, or secrets in the diff
- [ ] No `.db`, `.db-shm`, `.db-wal` files in the diff
- [ ] New endpoints use `@require_permission()` or `@login_required`
- [ ] New scanner checks validate/sanitise all inputs
- [ ] No new external dependencies added without running `pip-audit`

## Breaking Changes

<!-- If applicable, describe what breaks and how to migrate -->

## Related Issues

Closes #
