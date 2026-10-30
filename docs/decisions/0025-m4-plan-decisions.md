# 0025: M4 Plan Decisions: Re-contact Key, Admin Account, Archives, Packages

- Status: Accepted (owner, 2026-10-30)
- Date: 2026-10-30
- Decider: project owner
- Refines: decision 0024
- Resolves: M4 plan questions Q1 to Q5
  (`target/agent-workflow/20261030-m4-config-drivers/plan.md` §11)

## Decision

1. **Re-contact after the first reboot (Q1).** In Windows PE the agent
   generates its own P-384 job key and sends only the public half at
   confirmation.
   - The private key sits on the installed volume, readable only by
     SYSTEM, until the job ends. It is deleted when the post-setup steps
     finish.
   - After setup, the agent answers a server challenge with this key and
     receives a token valid only for that job.
   - No secret goes from the server to the device.
2. **Administrator account (Q2).** The built-in Administrator (RID 500) is
   enabled and given the escrowed password. No named account is created.
3. **CAB compression (Q3).** CAB archives that use LZX are refused by name
   until OPEN-ARC-1 is answered. Quantum, encrypted and multi-disk
   archives are refused too. Supported formats:
   - ZIP: stored, Deflate and Zip64;
   - CAB: uncompressed and MSZIP, single cabinet only.
4. **Driver results (Q4).** If DISM does not stage a driver, the install
   stops. There is no signature check at upload. Staging files are
   deleted, and the deletion is checked, before Windows first starts.
   "Nothing cached on the target" means nothing is left behind.
5. **Agent package signature (Q5).** "Operator-signed" means a detached
   ECDSA P-384 signature by a signer key that an administrator registers.
