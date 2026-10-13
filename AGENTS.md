# AGENTS.md

## WordPress connection check

This plugin and Harika are one connection. Programming, review, and tests treat both directions as a single check.

- The plugin calling Harika and Harika calling this plugin are two halves of the same result. A green result on only one half is not a connected website.
- A change to pairing, the site token, client ID, site ID, environment, the control endpoint, or the connection check is incomplete until both sides report the same fields: token accepted, client ID, site ID, environment, and website host.
- Harika remains the source for those values. This plugin reports what it stored. A mismatch is shown on both sides and does not overwrite the website in Harika.
- Tests for a connection change exercise both directions together. Saving settings, or posting an event, does not by itself prove the connection.
- Do not land a plugin-only connection check. The matching Harika change is part of the same work.
