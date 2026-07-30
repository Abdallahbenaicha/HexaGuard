# Contributing to SecuraX

Thank you for your interest in contributing. SecuraX is a research platform
with high standards for both engineering quality and scientific rigour.
Please read this guide before submitting a pull request.

---

## Philosophy

Before contributing, internalise the SecuraX philosophy:

1. **Every feature must answer**: *Does this increase scientific or engineering value?*
2. **Complexity is never a contribution.** Evidence is.
3. **Reproducibility is mandatory.** Nothing is complete unless another researcher
   can reproduce it.
4. **Never claim without measuring.** Never say a method is better unless a
   benchmark proves it.

If your contribution cannot connect to a research question in
`docs/RESEARCH_ROADMAP.md` or a documented engineering improvement, reconsider
whether it belongs in SecuraX.

---

## Development Environment

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### Setup

```bash
git clone https://github.com/Abdallahbenaicha/SecuraX.git
cd SecuraX/backend

python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

pip install -r requirements.txt
pip install pytest pytest-cov ruff bandit

cp .env.example .env
# Set SECRET_KEY to a 32+ char string
```

### Frontend

```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:5000" > .env.local
npm run dev
```

---

## Code Style

### Python (Backend)

We use **ruff** for linting and formatting. Configuration is in `backend/pyproject.toml`.

```bash
cd backend
ruff check .       # lint
ruff format .      # format (optional, not enforced in CI yet)
```

Key rules:
- Line length: 100 characters
- Follow PEP 8
- Type hints required for all public functions
- Every module must have a module-level docstring
- Every class and public function must have a docstring

### JavaScript (Frontend)

We use **ESLint** (configuration in `frontend/eslint.config.js`).

```bash
cd frontend
npm run lint
```

---

## Testing Requirements

**Every pull request must include tests.** No exceptions.

### Running tests

```bash
cd backend
pytest tests/ -v --cov=. --cov-report=term-missing
```

### What to test

- **New scanner check**: Unit test with mocked HTTP response verifying the check
  fires correctly and produces output conforming to `scanners/schema.py`.
- **Risk engine change**: Add a case to `tests/test_risk_engine.py` demonstrating
  the new behaviour. If changing weights, run the benchmark:
  ```bash
  pytest tests/test_risk_engine_benchmark.py -v -m benchmark
  ```
- **New API endpoint**: Integration test in `tests/test_api.py`.
- **Database change**: Test in `tests/test_database.py` using the `isolated_db` fixture.

### Coverage gate

CI enforces **60% minimum coverage** (`--cov-fail-under=60`). If your PR
significantly reduces coverage, it will be blocked.

---

## Pull Request Process

1. **Fork** the repository and create a branch:
   ```bash
   git checkout -b feat/your-feature-name    # new feature
   git checkout -b fix/your-bug-fix          # bug fix
   git checkout -b docs/your-doc-update      # documentation
   git checkout -b research/experiment-name  # research contribution
   ```

2. **Follow Conventional Commits** for commit messages:
   ```
   feat: add EPSS integration to risk engine
   fix: correct GDPR Art.32 false negative in _build_recommendations
   docs: add mathematical specification to RISK_ENGINE.md
   test: add benchmark cases for attack chain detection
   research: add E2 false positive study dataset
   ```

3. **Write or update tests** before pushing.

4. **Run the full CI check locally**:
   ```bash
   cd backend
   ruff check .
   pytest tests/ -v --cov=. --cov-fail-under=60 -m "not benchmark"
   bandit -r . -x venv,tests,archive_non_runtime -ll
   ```

5. **Open a Pull Request** and fill out the PR template completely.

---

## Research Contributions

Research contributions are especially welcome. A research contribution is:

- A new experimental dataset (see `docs/DATASETS.md`)
- A calibration study for the risk engine weights
- A false positive analysis for any scanner engine
- A new experiment protocol for `docs/RESEARCH_ROADMAP.md`
- A paper or thesis chapter based on SecuraX

For research contributions:
1. Open a GitHub Discussion first to align on methodology
2. Submit your dataset with a `metadata.json` (see `docs/DATASETS.md`)
3. Add your experiment to `docs/RESEARCH_ROADMAP.md`
4. Cite SecuraX using `CITATION.cff`

---

## Security Vulnerabilities

**Do not open a GitHub issue for security vulnerabilities.**
Report them privately as described in `SECURITY.md`.

---

## What We Will Not Accept

- Features that add complexity without measurable value
- AI/ML integrations without empirical evidence of improvement
- Microservices, message queues, or distributed system components
  (unless evidence shows they improve reproducibility or research quality)
- Cosmetic changes (UI tweaks, whitespace reformatting)
- Documentation that exaggerates or overclaims
- Code with no tests
- Commits that reduce coverage below 60%

---

## Licence

By contributing, you agree that your contributions will be licensed under
the [MIT License](LICENSE).
