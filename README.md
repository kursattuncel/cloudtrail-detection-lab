# CloudTrail Detection Lab

Synthetic AWS CloudTrail detections for teaching cloud security monitoring and SIEM logic.

## Job Signal

This repository is designed to demonstrate readiness for: **cloud SOC analyst, detection engineer, cybersecurity instructor**.

## Problem

Cloud monitoring is hard to demonstrate safely because real logs can include sensitive account data.

## What It Shows

- Run deterministic detections against synthetic CloudTrail fixtures.
- Cover root usage, missing MFA, logging tampering, and public S3 exposure events.
- Map each detection to an analyst question and response action.

## Quickstart

```bash
python -m pip install -e .
python -m unittest discover -s tests
python -m cloudtrail_detection_lab examples/cloudtrail.json
```

## Portfolio Talking Points

- I can turn ambiguous security work into repeatable workflows.
- I can write clear documentation for analysts, engineers, and learners.
- I can build safe, local-first examples that avoid real secrets and third-party targets.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md).

## Safety

This project is for defensive security, education, and local synthetic data only.
