# SecuraX Research Makefile
# ==========================
# Automates the full research pipeline from experiment to paper-ready outputs.
#
# Usage:
#   make experiment     → run full E1 experiment
#   make ablation       → run ablation study
#   make figures        → generate all figures
#   make benchmark      → run pytest benchmark suite
#   make all-research   → run everything in order
#   make verify-dataset → verify dataset integrity (checksums)
#   make paper-tables   → show path to generated LaTeX tables
#   make clean          → remove generated results (keep datasets)
#   make help           → show this help

.PHONY: help experiment ablation figures benchmark all-research \
        verify-dataset paper-tables dataset-manifest clean

PYTHON     = python
PYTEST     = pytest
SEED       = 42
EXPERIMENT = e1

# ── Help ──────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "SecuraX Research Makefile"
	@echo "========================="
	@echo ""
	@echo "Research pipeline:"
	@echo "  make experiment       Run E1 risk validation experiment"
	@echo "  make ablation         Run ablation study"
	@echo "  make figures          Generate all publication figures"
	@echo "  make benchmark        Run pytest benchmark (synthetic GT)"
	@echo "  make all-research     Run: experiment + ablation + figures"
	@echo ""
	@echo "Dataset management:"
	@echo "  make verify-dataset   Verify dataset SHA-256 checksums"
	@echo "  make dataset-manifest Regenerate dataset manifest file"
	@echo ""
	@echo "Paper utilities:"
	@echo "  make paper-tables     Show location of generated LaTeX tables"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean            Remove results/ (keep datasets/)"
	@echo "  make clean-all        Remove results/ AND papers/figures/"
	@echo ""
	@echo "Options:"
	@echo "  SEED=N         Random seed (default: 42)"
	@echo "  EXPERIMENT=ID  Experiment ID (default: e1)"
	@echo ""

# ── Research Pipeline ─────────────────────────────────────────────────────────

experiment:
	@echo "\n[MAKE] Running experiment $(EXPERIMENT) (seed=$(SEED))..."
	$(PYTHON) research/run_experiment.py \
		--experiment $(EXPERIMENT) \
		--seed $(SEED) \
		--output results/
	@echo "\n[MAKE] Results: results/$(EXPERIMENT)_risk_validation/"

ablation:
	@echo "\n[MAKE] Running ablation study..."
	$(PYTHON) research/ablation_study.py \
		--experiment $(EXPERIMENT) \
		--output results/ablation
	@echo "\n[MAKE] Ablation results: results/ablation/"

figures:
	@echo "\n[MAKE] Generating publication figures..."
	$(PYTHON) research/figures/generate_figures.py \
		--results results/ \
		--output papers/figures/
	@echo "\n[MAKE] Figures: papers/figures/"

benchmark:
	@echo "\n[MAKE] Running research benchmark suite..."
	cd backend && $(PYTEST) tests/test_risk_engine_benchmark.py \
		-v -m benchmark \
		--tb=short \
		-q
	@echo "\n[MAKE] Benchmark results: backend/tests/benchmark_results.json"

all-research: experiment ablation figures
	@echo "\n[MAKE] ✅ Full research pipeline complete."
	@echo "  Results: results/"
	@echo "  Figures: papers/figures/"
	@echo "  Tables:  results/*/paper_tables/"

# ── Dataset Management ────────────────────────────────────────────────────────

verify-dataset:
	@echo "\n[MAKE] Verifying dataset integrity..."
	$(PYTHON) research/verify_dataset.py \
		--manifest datasets/dataset-v1.0.0-manifest.json
	@echo "\n[MAKE] Dataset integrity verified."

dataset-manifest:
	@echo "\n[MAKE] Regenerating dataset manifest..."
	$(PYTHON) research/generate_manifest.py \
		--datasets datasets/ \
		--output datasets/dataset-v1.0.0-manifest.json
	@echo "\n[MAKE] Manifest: datasets/dataset-v1.0.0-manifest.json"

# ── Paper Utilities ───────────────────────────────────────────────────────────

paper-tables:
	@echo "\n[MAKE] LaTeX paper tables location:"
	@find results/ -name "*.tex" 2>/dev/null || echo "  Run 'make experiment' first."
	@echo ""

# ── Maintenance ───────────────────────────────────────────────────────────────

clean:
	@echo "\n[MAKE] Removing generated results (keeping datasets/)..."
	rm -rf results/
	@echo "[MAKE] Cleaned: results/"

clean-all: clean
	rm -rf papers/figures/
	@echo "[MAKE] Cleaned: papers/figures/"

# ── Development shortcuts ─────────────────────────────────────────────────────

test:
	@echo "\n[MAKE] Running full test suite..."
	cd backend && $(PYTEST) tests/ -v --tb=short

test-fast:
	@echo "\n[MAKE] Running fast tests (excluding benchmark)..."
	cd backend && $(PYTEST) tests/ -v --tb=short -m "not benchmark"

install-research:
	@echo "\n[MAKE] Installing research dependencies..."
	pip install matplotlib seaborn numpy
	@echo "\n[MAKE] Research dependencies installed."
