# 0016: Separate Administrative Database Role

- Status: Accepted (owner, 2026-10-27)
- Date: 2026-10-27
- Decider: project owner
- Refines: decisions 0008, 0012, 0015
- Resolves: review finding NIST-004 (M2)

## Context

The network-facing API's database role could create and change operators,
and the local-administrator check trusted a uid given on the same command
line. A compromise of the API process could therefore create an
administrator.

## Decision

1. A separate database role, `usgp_admin`, with its own TLS client
   certificate (decision 0012), is used only by local administrative
   commands (operator enrol/disable, audit verify).
2. The API's role, `usgp_app`, loses INSERT and UPDATE on operator records;
   it keeps only what serving the API needs.
3. The control on local administrative commands is possession of the
   `usgp_admin` client key, which deployment makes readable only by root
   (or a designated administrator account). The command also checks that it
   runs as root or as the owner of the server configuration file it loads
   (the file named on the command line);
   that check is a guard against mistakes, not the access control, and a
   uid supplied on the command line is never trusted on its own.
4. Operator changes made by `usgp_admin` are audited in the same chain.

## Consequences

- Deployment needs three database client certificates (owner for
  migrations, app for the service, admin for local commands).
- CI and test setup create the third role.
