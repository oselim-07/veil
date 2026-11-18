# Veil

Keeps personal and health data out of your AI coding agent.

Veil wraps a command (or reads piped text) and replaces sensitive data with placeholders before an AI agent sees it. It also prints a report of what was hidden: counts only, never the data itself.

## Usage

    veil run --report -- cat patient.txt
    echo "mail max@clinic.de" | veil --report

## What it detects

Emails, IBANs, insurance IDs, dates, phone numbers, passwords/tokens.

## Limits

Veil reduces risk but does not guarantee anything. Pattern matching cannot detect names yet. Use fake data for testing.
