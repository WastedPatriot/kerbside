# Security

kerbside reads files you already have. Those files are often the most sensitive thing on the laptop: names, descriptions, and the odd password someone typed into an attribute because the password manager was "in the other room".

The tool does not connect to a directory. Please don't add a quiet exception that does.

## Reporting a problem

If a report repeats a secret, or the tool does something it claims not to, open a GitHub issue on [WastedPatriot/kerbside](https://github.com/WastedPatriot/kerbside/issues). If the bug only makes sense with a real export attached, don't attach the export. Describe the shape of the data and mail the maintainer if you have a private channel.

Give it a day or two. This is a portfolio project, not a staffed SOC.

## What the report is allowed to say

A description that looks like it is holding a secret is named, and its length is given. The text itself stays in your export. If you find that text in `report.md`, `report.html`, or a JSON dump of the findings, that is a bug, not a feature.

Paths name rights that are already in the export (`GenericAll`, `DCSync`, and the rest). They are not a procedure.

## Your exports don't belong in git

Real BloodHound zips, ldap dumps, `.env` files, keys, and password databases are gitignored. The fixtures under `src/kerbside/data/fixtures` are fiction, including the password planted there so a test can check it never comes back out.

Deleting a file in a later commit does not delete it from history. If a real collection was pushed, treat every credential in it as burnt and rotate it.
