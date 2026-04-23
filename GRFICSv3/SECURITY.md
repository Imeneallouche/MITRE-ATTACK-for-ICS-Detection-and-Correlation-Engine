# Security Policy

## Purpose and Scope

This project provides a collection of containerized components intended for **educational, research, and training use in isolated environments**, such as an OT cybersecurity lab.

Many components in this repository **intentionally contain insecure configurations or known vulnerabilities** for learning and testing purposes. **These are not security bugs** and should not be reported as such.

**This project is not intended for use in production systems or on live, exposed networks.**

## Reporting Security Issues

We welcome reports of unintentional security issues, including:

 - Vulnerabilities that:
   - Escape the intended lab boundaries
   - Affect the host system unexpectedly
   - Enable access beyond the documented lab scope
- Supply-chain risks (e.g., compromised base images or dependencies)
- Issues that undermine the integrity or safety of the lab environment itself

**Please do not report intentionally vulnerable services or configurations that are documented or expected as part of the lab.**

To report an issue, contact:

📧 security@fortiphyd.com

Please do not report security issues via public GitHub issues or pull requests.

## What to Include in a Report

To help us evaluate the issue, please include:

 - A clear description of the issue
 - Which container(s) or components are affected
 - Steps to reproduce the behavior
 - Whether the issue affects the host or other systems outside the lab
 - Any relevant logs, screenshots, or proof-of-concept details

## Response Expectations

We aim to:
 - Acknowledge reports within 5 business days
 - Assess whether the issue is:
   - An intentional lab feature
   - A documentation gap
   - An unintentional security risk
 - Communicate next steps as appropriate

Fix timelines may vary depending on severity and project scope.

## Ethical Use and Authorization

This project includes tools and configurations commonly used for offensive security testing.

By using this project, you agree to:

 - Use it only in environments you own or are explicitly authorized to test
 - Avoid using these tools against networks, systems, or devices without permission
 - Comply with all applicable laws, regulations, and organizational policies
 - The maintainers do not condone or support unauthorized access, misuse, or illegal activity.

## Safe Harbor

We support responsible, good-faith security research conducted in accordance with this policy. We will not pursue legal action against individuals who:

 - Act in good faith
 - Avoid harm to others
 - Respect authorization boundaries
 - Follow this disclosure process

## Supported Versions

Security-related changes are generally applied to the latest version of the lab. Older versions may not receive updates.
