#!/bin/sh
# confirm which AWS account the CLI is signed in to
aws sts get-caller-identity --query Account --output text
