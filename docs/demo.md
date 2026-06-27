# Demo Guide

## What This Demonstrates

CloudTrail Detection Lab demonstrates writing cloud detection logic against safe synthetic logs.

## Five-Minute Demo

```bash
python -m pip install -e .
python -m unittest discover -s tests
python -m cloudtrail_detection_lab examples/cloudtrail.json
```

## Recruiter Talking Points

- Shows CloudTrail event understanding and detection engineering fundamentals.
- Covers root activity, missing MFA, logging tampering, and public S3 access changes.
- Works as both a portfolio project and classroom lab.

## Interview Narrative

This project is intentionally small and safe. It shows that I can define a defensive security workflow, write explainable Python, include tests, document the usage path, and keep the project scoped to synthetic local data.
