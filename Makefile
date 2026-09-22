.PHONY: demo test check generate train model-eval loadtest evaluate preflight evidence live-proof capture-proof judge-demo
generate:
	python3 traffic-gen/generators/generate_scenarios.py
demo: generate
	./scripts/run_demo.sh
test:
	python3 -m unittest discover -s tests -v
check:
	python3 -m compileall -q .
	docker compose config
train:
	docker compose --profile tools run --build --rm trainer
model-eval: train
	docker compose --profile tools run --rm evaluator
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
