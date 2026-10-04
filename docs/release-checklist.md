# Before a stable integrated release

- [x] 62 standalone tests, synthetic demo, journal backup/restore and raw JSONL export pass locally.
- [x] GitHub CI passes on Linux, macOS and Windows with Node 24 and 26.
- [x] Schema compatibility, private POSIX file permissions and explicit database paths documented in operations.md.
- [x] Corrected Windows core CI passes. It does not certify Windows ACL privacy or Hermes.
- [ ] Verify the optional plugin against a pinned live Hermes gateway version.
- [ ] Add an installation/configuration helper that validates private permissions and explicit paths.
- [ ] Measure search and delivery latency on larger synthetic stores.
- [ ] Independently review access controls against the live host integration.
- [ ] Verify optional Chroma projection before advertising support.

Events are immutable. Export supports a cutoff; there is no automatic deletion of old events.
The standalone tests and demo do not verify LLM fact extraction quality, truth,
or integration into the complete Wiki or MemPalace application.
There is no new graphical interface, so rendered visual acceptance does not apply.
