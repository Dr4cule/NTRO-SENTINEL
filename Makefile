.PHONY: demo test check generate train model-eval loadtest evaluate preflight evidence live-proof capture-proof judge-demo
# TRAIN_BACKEND=docker (default) runs the pinned, hermetic toolchain. TRAIN_BACKEND=local uses
# the host interpreter and the host scikit-learn, which is what you want for iterating locally
# (and avoids needing a working Docker daemon just to regenerate a JSON artifact).
TRAIN_BACKEND ?= docker
generate:
	python3 traffic-gen/generators/generate_scenarios.py
	python3 traffic-gen/generators/generate_lateral_c2.py
	python3 traffic-gen/generators/generate_benign_internal.py
demo: generate
	./scripts/run_demo.sh
test:
	python3 -m unittest discover -s tests -v
check:
	python3 -m compileall -q .
	docker compose config
train:
ifeq ($(TRAIN_BACKEND),local)
	python3 -m models.train_models
else
	docker compose --profile tools run --build --rm trainer
endif
model-eval: train
ifeq ($(TRAIN_BACKEND),local)
	python3 -m models.evaluate_models
else
	docker compose --profile tools run --rm evaluator
endif
loadtest: generate
	python3 -m eval.loadtest
evaluate: generate
	./scripts/run_evaluation.sh
preflight:
	./scripts/demo_preflight.sh
evidence:
	./scripts/export_evidence_bundle.sh
live-proof:
	./scripts/run_live_capture_proof.sh
capture-proof:
	./scripts/run_end_to_end_capture_proof.sh
judge-demo:
	./scripts/run_judge_demo.sh
