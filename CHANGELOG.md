# Changelog

## 0.0.1 (2026-06-27)


### Features

* **cli:** one-shot headless capture by IP ([7c879c2](https://github.com/shauneccles/glinet-profiler/commit/7c879c203d7ff57d89a3d1adf8c8a6e951430d33))
* fetch the live registry at runtime; drop bundled data/site/bot (own repo) ([2c581a3](https://github.com/shauneccles/glinet-profiler/commit/2c581a37060ed88be98bfeb56ff71a3e0b794664))
* glinet-profiler local capture launcher (extracted from gli4py) ([bf2c1be](https://github.com/shauneccles/glinet-profiler/commit/bf2c1be0e2ff9c9f7ce323884680ef37ce635613))
* **launcher:** live capture progress (NDJSON streaming + UI panel + logging) ([0a70368](https://github.com/shauneccles/glinet-profiler/commit/0a70368b451cf6b9d0a018f52fcb1fa8219e4e69))
* local GL.iNet challenge-response login (libpass + hashlib) ([53e82aa](https://github.com/shauneccles/glinet-profiler/commit/53e82aad499ad671b9f3d910328003d4a17b93f6))
* move the enumerator engine into glinet_profiler (paramiko core) ([3ba5118](https://github.com/shauneccles/glinet-profiler/commit/3ba511813e5b5f54ce43b2220ab611809b7c54a0))
* point launcher Submit at the issue form (auto-label submission) ([38caf40](https://github.com/shauneccles/glinet-profiler/commit/38caf402f1fd8b9431f20a0a2a31987c8c5d6dd8))
* public registry browser site (ported, hardened escaping) ([8e4f6ea](https://github.com/shauneccles/glinet-profiler/commit/8e4f6ea6251e0ba190f41438cf6cf400f047048d))
* registry manifest builder (build_manifest + rebuild + CLI) ([d59163b](https://github.com/shauneccles/glinet-profiler/commit/d59163be2a18f0ba3d6f73a1de35fe142ba5962c))
* rewire capture/ingest to local engine+login; drop gli4py; SSH default ([38872a4](https://github.com/shauneccles/glinet-profiler/commit/38872a48567cfbd7e0e5d311aaded06ed2e38b79))
* **ui:** SSH ground-truth checked by default ([1ff8285](https://github.com/shauneccles/glinet-profiler/commit/1ff8285c741f2413954d05b99518b6f283c45c11))
* validate + ingest submitted profiles (glinet_profiler.ingest + CLI) ([710a2f9](https://github.com/shauneccles/glinet-profiler/commit/710a2f912ab4aecb821d44da1878ea3bbbc797da))


### Bug Fixes

* **ci:** pass attachment URL via env to curl (avoid shell injection) ([8c4b2c7](https://github.com/shauneccles/glinet-profiler/commit/8c4b2c7dd6bb0326eef3274b1f9113f5f3950730))
* drop stale gli4py[ssh] hint from SshUnavailable message ([3bfd73b](https://github.com/shauneccles/glinet-profiler/commit/3bfd73b8994fdf31a12377e93f0a47101c43a6e2))
* **launcher:** flush final NDJSON line; assert progress-count in structural test ([e8b2f0b](https://github.com/shauneccles/glinet-profiler/commit/e8b2f0bf5f6f69f03cb54e99568b4f5ebf703faf))
* **launcher:** skip browser auto-open under WSL; graceful Ctrl+C shutdown (no traceback) ([42980e8](https://github.com/shauneccles/glinet-profiler/commit/42980e815c6077595bc8c6b30a21a30ece7f2a19))
* **login:** clear error on invalid challenge; sha-determinism + username tests ([37b5a72](https://github.com/shauneccles/glinet-profiler/commit/37b5a7281a7a125c50dad4c6f64604a191ba5904))
* random heredoc delimiter + validate model/firmware are strings ([237a61d](https://github.com/shauneccles/glinet-profiler/commit/237a61d951a1db7b07363f84bf79f627233b3a3e))
* **registry:** guard non-dict manifest; cover registry-url threading + known-device CLI ([605f907](https://github.com/shauneccles/glinet-profiler/commit/605f907f5ce7e8e31d87d4d61a1305abbd5bd719))


### Documentation

* correct stale copy (no gli4py dependency; registry/site moved to glinet-registry) ([2ff1694](https://github.com/shauneccles/glinet-profiler/commit/2ff1694639f9414b8c94d9c783ec3385bca25257))
* implementation plan for re-homing the API browser (Phase 2) ([6d6dd39](https://github.com/shauneccles/glinet-profiler/commit/6d6dd39552aebe8a10cfb731bbf947d9de19c021))
* implementation plan for the submission PR bot ([163ec05](https://github.com/shauneccles/glinet-profiler/commit/163ec056ed585734075b2e4cbda178170026d90d))
* implementation plan to internalize the enumerator + drop gli4py ([25e3df9](https://github.com/shauneccles/glinet-profiler/commit/25e3df917ed3b0f3dbaee0025e66c15992efc95a))
* plan to split the registry into its own repo (runtime fetch) ([0f0c599](https://github.com/shauneccles/glinet-profiler/commit/0f0c599faa910ae565c54f329959711d95a90a80))
* preserve Phase-1 launcher design (spec + plan) from gli4py staging ([69eb55d](https://github.com/shauneccles/glinet-profiler/commit/69eb55dc998f3fd8a3f26534b73f25cf51edf661))
* spec automated profile-submission PR bot ([2c9b5ca](https://github.com/shauneccles/glinet-profiler/commit/2c9b5ca5719ca799b860a5fb70c90d0ebc9acf37))
* spec internalize the enumerator; drop gli4py entirely ([06f1947](https://github.com/shauneccles/glinet-profiler/commit/06f1947a90256bf2b8c4fe50626ca4e98fb818f5))
* spec re-home the API browser (Phase 2) ([36a5718](https://github.com/shauneccles/glinet-profiler/commit/36a5718a141b2c48d3555d9a6b47f45ae1c6aa19))
* spec split the registry into its own repo (runtime fetch) ([9acc6a0](https://github.com/shauneccles/glinet-profiler/commit/9acc6a0b4544bff2afc3ba135817fa9af8bf0a28))


### Continuous Integration

* release automation (release-please + PyPI trusted publishing) ([a88409b](https://github.com/shauneccles/glinet-profiler/commit/a88409b5ca2a886235683c105e014b750fcb3959))
