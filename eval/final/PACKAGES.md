# Packages stored in the PkgGuard database

_Generated 2026-09-19 20:56 from the live DynamoDB table. **387 records** in total._

**How to read it.** *Verdict* is PkgGuard's final call. *Decided by* is the layer that made it: `intel` (a threat feed), `sandbox` (proof from actually running it), `ai` (the AI code review), `rules` (static rules). *Sandbox* is COMPLETE (it ran and the entry file loaded), PARTIAL (it ran but some things could not be observed) or `not run`. *Key evidence* lists the strongest rule IDs behind a flagged verdict.

## Summary

| # | Category | Packages | Verdicts |
|---|---|---|---|
| 1 | Original set | 59 | 1 MALICIOUS, 3 SUSPICIOUS, 55 SAFE |
| 2 | Evaluation: published with malicious intent | 80 | 64 MALICIOUS, 4 SUSPICIOUS, 12 SAFE |
| 3 | Evaluation: legitimate packages that were compromised | 20 | 13 MALICIOUS, 3 SUSPICIOUS, 4 SAFE |
| 4 | Evaluation: ordinary clean packages | 168 | 1 MALICIOUS, 11 SUSPICIOUS, 156 SAFE |
| 5 | Evaluation: legitimate but tricky packages | 30 | 2 SUSPICIOUS, 28 SAFE |
| 6 | Scanned by accident (lockfile upload) | 30 | 10 SAFE, 20 (stopped) |
| | **Total** | **387** | 79 MALICIOUS, 23 SUSPICIOUS, 265 SAFE, 20 (stopped) |

## 1. Original set (59)

Well-known packages scanned earlier in the project and re-scanned with the current pipeline (sandbox with dependencies + AI). Almost all are ordinary popular libraries; `faker` (a sabotaged release) and `safedep-test-pkg` (a known test-malware package) are the deliberate exceptions.

| Package | Version | Verdict | Decided by | Sandbox | Key evidence |
|---|---|---|---|---|---|
| `safedep-test-pkg` | 0.1.3 | MALICIOUS | intel | COMPLETE | malware |
| `faker` | 6.6.6 | SUSPICIOUS | ai | PARTIAL |  |
| `next` | 16.3.5 | SUSPICIOUS | rules | PARTIAL | decode_and_run |
| `vite` | 8.3.0 | SUSPICIOUS | rules | COMPLETE | sandbox:sandbox_detection, decode_and_run |
| `@babel/core` | 8.0.5 | SAFE | ai | COMPLETE |  |
| `axios` | 1.20.0 | SAFE | ai | COMPLETE |  |
| `bcrypt` | 6.0.0 | SAFE | ai | COMPLETE | install_script |
| `body-parser` | 2.3.0 | SAFE | ai | COMPLETE |  |
| `chalk` | 6.0.0 | SAFE | ai | COMPLETE |  |
| `cheerio` | 1.2.0 | SAFE | ai | COMPLETE |  |
| `commander` | 15.0.0 | SAFE | ai | COMPLETE |  |
| `cookie-parser` | 1.4.7 | SAFE | ai | COMPLETE | new_publisher |
| `cors` | 2.8.6 | SAFE | ai | COMPLETE | new_publisher |
| `dayjs` | 1.11.23 | SAFE | ai | COMPLETE |  |
| `debug` | 4.4.3 | SAFE | ai | COMPLETE |  |
| `dotenv` | 17.4.2 | SAFE | ai | COMPLETE |  |
| `esbuild` | 0.28.2 | SAFE | ai | COMPLETE | install_script, exec |
| `eslint` | 10.10.0 | SAFE | ai | COMPLETE |  |
| `express` | 5.2.1 | SAFE | ai | COMPLETE |  |
| `glob` | 13.0.6 | SAFE | ai | COMPLETE |  |
| `husky` | 9.1.7 | SAFE | ai | COMPLETE |  |
| `is-number` | 7.0.0 | SAFE | ai | COMPLETE |  |
| `is-odd` | 3.0.1 | SAFE | ai | COMPLETE |  |
| `jest` | 30.5.1 | SAFE | ai | COMPLETE |  |
| `jsonwebtoken` | 9.0.3 | SAFE | ai | COMPLETE | new_publisher |
| `left-pad` | 1.3.0 | SAFE | ai | COMPLETE |  |
| `lodash` | 4.18.1 | SAFE | ai | COMPLETE |  |
| `minimist` | 1.2.8 | SAFE | ai | COMPLETE |  |
| `moment` | 2.31.0 | SAFE | ai | COMPLETE | hex_escapes |
| `mongoose` | 9.10.1 | SAFE | ai | COMPLETE |  |
| `ms` | 2.1.3 | SAFE | ai | COMPLETE |  |
| `multer` | 2.4.0 | SAFE | ai | COMPLETE |  |
| `mysql2` | 3.24.4 | SAFE | ai | COMPLETE |  |
| `nanoid` | 6.0.1 | SAFE | ai | COMPLETE |  |
| `node-fetch` | 3.3.2 | SAFE | ai | COMPLETE |  |
| `nodemon` | 3.1.14 | SAFE | ai | COMPLETE |  |
| `pg` | 8.23.0 | SAFE | ai | COMPLETE |  |
| `picocolors` | 1.1.1 | SAFE | ai | COMPLETE |  |
| `pino` | 10.3.1 | SAFE | ai | COMPLETE | exfiltration |
| `postcss` | 8.5.28 | SAFE | ai | COMPLETE |  |
| `prettier` | 3.9.7 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `puppeteer` | 25.11.0 | SAFE | ai | COMPLETE | install_script |
| `qs` | 6.16.0 | SAFE | ai | COMPLETE |  |
| `react` | 19.3.0 | SAFE | ai | COMPLETE |  |
| `react-dom` | 19.3.0 | SAFE | ai | PARTIAL |  |
| `redis` | 6.2.1 | SAFE | ai | COMPLETE |  |
| `rimraf` | 6.1.3 | SAFE | ai | COMPLETE |  |
| `semver` | 7.8.5 | SAFE | ai | COMPLETE |  |
| `sharp` | 0.35.4 | SAFE | ai | COMPLETE |  |
| `socket.io` | 4.8.3 | SAFE | ai | COMPLETE |  |
| `tailwindcss` | 4.3.3 | SAFE | ai | COMPLETE |  |
| `typescript` | 7.0.2 | SAFE | ai | COMPLETE |  |
| `unique-names-generator` | 4.7.1 | SAFE | ai | COMPLETE |  |
| `uuid` | 14.0.2 | SAFE | ai | COMPLETE |  |
| `webpack` | 5.111.0 | SAFE | ai | COMPLETE |  |
| `winston` | 3.19.0 | SAFE | ai | COMPLETE |  |
| `ws` | 8.21.3 | SAFE | ai | COMPLETE |  |
| `yargs` | 18.1.0 | SAFE | ai | COMPLETE |  |
| `zod` | 4.6.5 | SAFE | ai | COMPLETE |  |

## 2. Evaluation: published with malicious intent (80)

Real malware samples from Datadog's public dataset: typosquats, dependency-confusion placeholders, credential stealers. They are labeled evaluation samples, not threats found in the wild, and many were removed from npm long ago. Expected: flagged.

| Package | Version | Verdict | Decided by | Sandbox | Key evidence |
|---|---|---|---|---|---|
| `@apple-pay-trust/destroy` | 99.0.1 | MALICIOUS | ai | COMPLETE | install_script, high_version |
| `@eooce/sbx` | 1.0.0 | MALICIOUS | ai | PARTIAL | sandbox:decoy_read, telegram_bot_api |
| `@klarna-travel-platform/travel-booking-shared-types` | 99.99.99 | MALICIOUS | ai | COMPLETE | install_script, high_version |
| `@liquid-web/app-services` | 1.2.9213 | MALICIOUS | sandbox | COMPLETE | sandbox:canary_exfil, sandbox:suspicious_network, install_script, sensitive_path |
| `acceptable_gazelle_z3n` | 4.1.3 | MALICIOUS | ai | PARTIAL |  |
| `actor-alarms` | 99.99.99 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, high_version |
| `agus-tongseng59-breki` | 4.4.2 | MALICIOUS | ai | COMPLETE |  |
| `bdc-materials` | 7.1.9 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, exfiltration |
| `bignumex` | 1.0.1 | MALICIOUS | ai | COMPLETE |  |
| `cbt-gs-switcher-library` | 99.0.0 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, install_script, high_version |
| `com.unity.visualscripting` | 1.8.0 | MALICIOUS | ai | PARTIAL | sandbox:unexpected_network, install_script |
| `confluence-analytics-support` | 99.99.1 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, sandbox:suspicious_process, install_script |
| `contentsdk-node` | 1.0.0 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, request_capture_service, exfiltration |
| `cookie-validate` | 2.2.4 | MALICIOUS | sandbox | COMPLETE | sandbox:canary_exfil, sandbox:unexpected_network, install_script, javascript_obfuscator |
| `cruel_moth_z3n` | 4.4.1 | MALICIOUS | ai | PARTIAL |  |
| `dian-botok60-breki` | 2.2.2 | MALICIOUS | ai | COMPLETE |  |
| `digits-electron-src` | 1.0.1 | MALICIOUS | sandbox | PARTIAL | sandbox:canary_exfil, install_script |
| `dirty_hawk_z3n` | 1.1.4 | MALICIOUS | ai | PARTIAL |  |
| `disabled_native_dep` | 2.9.9 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, request_capture_service |
| `dspmobile` | 96.16.76 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script |
| `elf-stats-caroling-workshop-885` | 5.5.3 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, sandbox:sandbox_detection, install_script, request_capture_service |
| `elf-stats-shimmering-nightcap-245` | 99.9.25 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, high_version |
| `erick-tahutek9-ruro` | 1.4.2 | MALICIOUS | ai | COMPLETE |  |
| `eth-keyringcontrler` | 9.0.0 | MALICIOUS | ai | PARTIAL | sandbox:unexpected_network, install_script, javascript_obfuscator |
| `fajar-taiwan34-miaww` | 3.2.1 | MALICIOUS | ai | COMPLETE |  |
| `gita-sate56-sluey` | 4.1.4 | MALICIOUS | ai | COMPLETE |  |
| `hrp987` | 1.0.0 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, sandbox:suspicious_process, install_script, exfiltration |
| `inclined_cardinal_z3n` | 4.3.3 | MALICIOUS | ai | PARTIAL |  |
| `indah-tomat100-sluey` | 3.2.2 | MALICIOUS | ai | COMPLETE |  |
| `kresna-lontong7-sluey` | 1.3.1 | MALICIOUS | ai | COMPLETE |  |
| `lisa-brongkos38-breki` | 4.3.2 | MALICIOUS | ai | COMPLETE |  |
| `lutfi-kripik40-miaww` | 4.2.1 | MALICIOUS | ai | COMPLETE |  |
| `mathjax-v3` | 1.0.1 | MALICIOUS | sandbox | PARTIAL | sandbox:canary_exfil, sandbox:suspicious_network, install_script, raw_ip |
| `merlin-transformer` | 13.7.9 | MALICIOUS | ai | PARTIAL | install_script, request_capture_service |
| `midcorp` | 1.1.9 | MALICIOUS | ai | COMPLETE |  |
| `model-viewer-space-opera` | 1.1.0 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, sandbox:suspicious_process, install_script |
| `moscova-plural-json-parser` | 1.0.0 | MALICIOUS | ai | PARTIAL |  |
| `mulyono-lapis72-sluey` | 2.3.3 | MALICIOUS | ai | COMPLETE |  |
| `next-tab` | 1.0.0 | MALICIOUS | sandbox | PARTIAL | sandbox:reverse_shell, sandbox:suspicious_network, install_script, request_capture_service |
| `nimiq-pool` | 1.0.1 | MALICIOUS | ai | PARTIAL | install_script, request_capture_service |
| `node-loggerx` | 0.3.0 | MALICIOUS | sandbox | PARTIAL | sandbox:canary_exfil, install_script, exfiltration |
| `nodenetbanxsdk` | 25.6.7 | MALICIOUS | ai | COMPLETE | install_script, exfiltration |
| `ofjaaah-auth-module` | 999.0.0 | MALICIOUS | ai | COMPLETE | install_script |
| `onyx-ssi-sdk-examples` | 2.0.0 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, request_capture_service |
| `open-answer-engine-frontend` | 99.9.8 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, sandbox:suspicious_process, install_script, high_version |
| `parentu` | 1.0.0 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, install_script |
| `pino-logging` | 2.2.3 | MALICIOUS | sandbox | PARTIAL | sandbox:canary_exfil, install_script |
| `pixelary` | 3.3.3 | MALICIOUS | ai | PARTIAL | install_script |
| `pp-react-segmented-controller` | 99.0.0 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_process, install_script, high_version |
| `putri-soto15-sluey` | 4.3.2 | MALICIOUS | ai | COMPLETE |  |
| `react-modal-select` | 1.0.0 | MALICIOUS | ai | COMPLETE | sandbox:unexpected_network, install_script, dynamic_code |
| `react-svg-anchor` | 1.0.0 | MALICIOUS | ai | COMPLETE |  |
| `rollup-plugin-amd-output-enhance` | 6.5.8 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, exfiltration |
| `seller-base.preview` | 6.5.8 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, exfiltration |
| `siska-mieaceh96-miaww` | 3.1.3 | MALICIOUS | ai | COMPLETE |  |
| `sprocket-webapp-poc` | 99.99.99 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, install_script, high_version |
| `tailwind-mouse-icon` | 1.0.2 | MALICIOUS | ai | PARTIAL |  |
| `tiara-gandul77-riris` | 4.1.4 | MALICIOUS | ai | COMPLETE |  |
| `timify-packager` | 2.0.0 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, sandbox:suspicious_process, install_script |
| `tomi-kue89-sluey` | 1.1.3 | MALICIOUS | ai | COMPLETE |  |
| `tsl-select-trigger` | 5.0.0 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_network, install_script, exfiltration |
| `udin-sate14-miaww` | 3.3.2 | MALICIOUS | ai | COMPLETE |  |
| `upstartportal` | 99.99.1 | MALICIOUS | sandbox | COMPLETE | sandbox:canary_exfil, sandbox:decoy_read, install_script, high_version |
| `vscode-dotnet-sdk` | 1.0.0 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_network, request_capture_service, exfiltration |
| `bg-core-payments-automation` | 1.0.0 | SUSPICIOUS | ai | PARTIAL |  |
| `hpglobaldata` | 1.0.0 | SUSPICIOUS | rules | COMPLETE | sandbox:suspicious_network, install_script, request_capture_service |
| `joni-rojak73-sluey` | 4.1.2 | SUSPICIOUS | ai | COMPLETE |  |
| `tailwindthml-flips` | 1.0.3 | SUSPICIOUS | ai | PARTIAL |  |
| `@walletwave/backend` | 1.1.0 | SAFE | ai | PARTIAL |  |
| `agus-rujak20-wekto` | 1.2.4 | SAFE | ai | COMPLETE |  |
| `balanced_harrier_z3n` | 4.3.3 | SAFE | ai | COMPLETE |  |
| `elf-stats-lanternlit-giftbox-663` | 1.0.0 | SAFE | ai | COMPLETE |  |
| `epic-ue-shared` | 1.0.0 | SAFE | ai | PARTIAL |  |
| `epic-webpack-hot-dev-client` | 1.0.0 | SAFE | ai | PARTIAL |  |
| `fast-utilz` | 1.0.0 | SAFE | ai | COMPLETE |  |
| `francium-ui` | 1.0.0 | SAFE | ai | COMPLETE | install_script |
| `modify-setting` | 2.4.3 | SAFE | ai | COMPLETE |  |
| `trivandrum` | 0.0.0-dev-202603280649 | SAFE | ai | PARTIAL | install_script |
| `ui-data-layer` | 1.0.0 | SAFE | ai | COMPLETE | install_script |
| `ve-hemi-actions` | 1.0.0 | SAFE | ai | COMPLETE | install_script |

## 3. Evaluation: legitimate packages that were compromised (20)

Real, normally-legitimate packages whose specific versions were hijacked in supply-chain attacks (for example the 2025 npm worm). Also labeled evaluation samples. Expected: flagged.

| Package | Version | Verdict | Decided by | Sandbox | Key evidence |
|---|---|---|---|---|---|
| `@antstackio/express-graphql-proxy` | 0.2.8 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_process, install_script, exfiltration |
| `@antv/x6-geometry` | 2.2.5 | MALICIOUS | ai | PARTIAL | install_script, exfiltration |
| `@emilgroup/document-uploader` | 0.0.10 | MALICIOUS | ai | COMPLETE | sandbox:persistence, install_script, sensitive_path |
| `@emilgroup/public-api-sdk-node` | 1.35.1 | MALICIOUS | ai | COMPLETE | install_script, exec |
| `@ensdomains/test-utils` | 1.3.1 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_process, install_script, exfiltration |
| `@nstudio/nativescript-loading-indicator` | 5.0.1 | MALICIOUS | sandbox | PARTIAL | sandbox:canary_exfil, sandbox:dropper_exec, install_script, request_capture_service |
| `@quick-start-soft/quick-git-clean-markdown` | 1.4.2511142126 | MALICIOUS | ai | COMPLETE | sandbox:suspicious_process, install_script, exfiltration |
| `@quick-start-soft/quick-markdown-translator` | 1.4.2509202331 | MALICIOUS | ai | COMPLETE | sandbox:decoy_read, sandbox:suspicious_process, install_script, exfiltration |
| `airpilot` | 0.8.8 | MALICIOUS | ai | COMPLETE | request_capture_service |
| `autotel-mongoose` | 6.0.1 | MALICIOUS | ai | PARTIAL | sandbox:suspicious_process |
| `babel-plugin-react-pure-component` | 0.1.6 | MALICIOUS | ai | COMPLETE | sandbox:persistence, install_script, sensitive_path |
| `ember-headless-table` | 2.1.5 | MALICIOUS | sandbox | PARTIAL | sandbox:canary_exfil, sandbox:dropper_exec, install_script, request_capture_service |
| `react-complaint-image` | 0.0.32 | MALICIOUS | ai | PARTIAL | request_capture_service |
| `@tallyui/core` | 0.2.1 | SUSPICIOUS | ai | PARTIAL | install_script, exec |
| `github-action-for-generator` | 2.1.27 | SUSPICIOUS | rules | COMPLETE | sandbox:decoy_read, sandbox:suspicious_process, install_script, exfiltration |
| `zuper-sdk` | 1.0.57 | SUSPICIOUS | ai | COMPLETE | sandbox:suspicious_process, install_script, exfiltration |
| `@mastra/mcp` | 1.10.1 | SAFE | ai | PARTIAL |  |
| `@mastra/opensearch` | 1.0.3 | SAFE | ai | PARTIAL |  |
| `@tanstack/router-cli` | 1.166.46 | SAFE | ai | COMPLETE | sandbox:sandbox_detection, javascript_obfuscator |
| `@uipath/data-fabric-tool` | 1.0.2 | SAFE | ai | PARTIAL | sandbox:sandbox_detection, install_script, exec |

## 4. Evaluation: ordinary clean packages (168)

A seeded random draw of popular npm packages (2 more were skipped as too large). Expected SAFE, so any other verdict here is a false alarm.

| Package | Version | Verdict | Decided by | Sandbox | Key evidence |
|---|---|---|---|---|---|
| `@typescript/typescript6` | 6.0.2 | MALICIOUS | ai | COMPLETE |  |
| `@apps-in-toss/cli` | 3.4.1 | SUSPICIOUS | rules | COMPLETE | exfiltration |
| `@farm.js/core` | 0.1.0-beta.102 | SUSPICIOUS | rules | PARTIAL | fresh_publish, decode_and_run |
| `@google/gemini-cli` | 0.60.0 | SUSPICIOUS | rules | COMPLETE | sandbox:decoy_read, sandbox:eval_payload, exfiltration |
| `@lobehub/seo-cli` | 1.7.0 | SUSPICIOUS | ai | COMPLETE | sandbox:decoy_read |
| `@uipath/cli` | 1.202.0 | SUSPICIOUS | rules | PARTIAL | exfiltration, decode_and_run |
| `awing-library` | 2.1.2-stable.46 | SUSPICIOUS | rules | PARTIAL | decode_and_run |
| `blun-king-cli` | 9.1.601 | SUSPICIOUS | rules | PARTIAL | install_script, fresh_publish |
| `drizzle-kit` | 0.31.10 | SUSPICIOUS | rules | COMPLETE | sandbox:decoy_read, decode_and_run |
| `filestack-js` | 3.51.6 | SUSPICIOUS | rules | PARTIAL | decode_and_run |
| `mcp-use` | 2.5.1 | SUSPICIOUS | rules | COMPLETE | fresh_publish, exfiltration |
| `mobbdev` | 1.5.18 | SUSPICIOUS | rules | PARTIAL | sandbox:sandbox_detection, install_script, exfiltration |
| `@a2ui/web_core` | 0.11.0 | SAFE | ai | COMPLETE | sensitive_path |
| `@accio-ai/cli` | 0.1.59 | SAFE | ai | COMPLETE | install_script |
| `@algolia/abtesting` | 1.25.0 | SAFE | ai | COMPLETE |  |
| `@angular-devkit/schematics-cli` | 22.1.8 | SAFE | ai | COMPLETE |  |
| `@aws-amplify/amplify-category-hosting` | 3.5.46 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `@aws-cdk/asset-awscli-v1` | 2.2.294 | SAFE | ai | COMPLETE |  |
| `@aws-cdk/cli-plugin-contract` | 2.182.2 | SAFE | ai | COMPLETE |  |
| `@base44/sdk` | 0.8.48 | SAFE | ai | COMPLETE |  |
| `@bugsnag/js` | 8.10.0 | SAFE | ai | COMPLETE |  |
| `@chakra-ui/react-use-timeout` | 2.1.0 | SAFE | ai | COMPLETE |  |
| `@chialab/esbuild-rna` | 0.19.3 | SAFE | ai | COMPLETE |  |
| `@contentstack/cli-cm-export` | 2.0.1 | SAFE | ai | COMPLETE | sandbox:decoy_read, sandbox:sandbox_detection |
| `@cspell/dict-typescript` | 3.2.3 | SAFE | ai | PARTIAL |  |
| `@cyclonedx/cyclonedx-library` | 10.3.0 | SAFE | ai | COMPLETE | fresh_publish |
| `@deriv-com/utils` | 0.0.59 | SAFE | ai | COMPLETE |  |
| `@ecl/utility-flex` | 5.3.0 | SAFE | ai | COMPLETE |  |
| `@editorjs/personality` | 2.0.2 | SAFE | ai | PARTIAL |  |
| `@ethersproject/hdnode` | 5.8.0 | SAFE | ai | COMPLETE |  |
| `@expressots/core` | 4.3.0 | SAFE | ai | PARTIAL |  |
| `@expressots/shared` | 4.3.0 | SAFE | ai | COMPLETE |  |
| `@grafana/scenes-react` | 8.18.2 | SAFE | ai | PARTIAL | fresh_publish |
| `@grpc/reflection` | 1.0.4 | SAFE | ai | PARTIAL |  |
| `@heroku-cli/notifications` | 1.2.9 | SAFE | ai | COMPLETE |  |
| `@hugerte/framework-integration-shared` | 1.2.0 | SAFE | ai | COMPLETE |  |
| `@iconify/react` | 6.0.2 | SAFE | ai | PARTIAL |  |
| `@js-joda/core` | 6.1.0 | SAFE | ai | COMPLETE |  |
| `@kenkaiiii/gg-agent` | 5.60.4 | SAFE | ai | COMPLETE | fresh_publish |
| `@ledgerhq/hw-transport-node-hid-noevents` | 6.36.0 | SAFE | ai | COMPLETE |  |
| `@lit/react` | 1.0.8 | SAFE | ai | COMPLETE |  |
| `@loaders.gl/pmtiles` | 4.5.1 | SAFE | ai | COMPLETE |  |
| `@magda/minion-framework` | 6.2.1 | SAFE | ai | COMPLETE |  |
| `@mdx-js/react` | 3.1.1 | SAFE | ai | PARTIAL |  |
| `@middy/http-response-serializer` | 7.9.2 | SAFE | ai | PARTIAL |  |
| `@modern-js/server` | 3.9.2 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `@mongosh/cli-repl` | 2.12.0 | SAFE | ai | PARTIAL | fresh_publish |
| `@neo4j-nvl/base` | 2.0.0 | SAFE | ai | PARTIAL |  |
| `@nestjs/swagger` | 12.0.1 | SAFE | ai | PARTIAL |  |
| `@nestjs/typeorm` | 12.0.1 | SAFE | ai | PARTIAL |  |
| `@netlify/functions-utils` | 7.1.10 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `@nocobase/cli` | 2.2.15 | SAFE | ai | PARTIAL | fresh_publish |
| `@openrouter/agent` | 0.11.0 | SAFE | ai | COMPLETE |  |
| `@oxc-parser/binding-linux-s390x-gnu` | 0.150.0 | SAFE | ai | PARTIAL |  |
| `@oxc-transform/binding-linux-arm64-musl` | 0.150.0 | SAFE | ai | PARTIAL |  |
| `@pgpmjs/logger` | 2.26.0 | SAFE | ai | COMPLETE |  |
| `@pie-players/pie-tool-ruler` | 0.3.73 | SAFE | ai | PARTIAL | fresh_publish |
| `@pixiv/three-vrm-node-constraint` | 3.5.5 | SAFE | ai | PARTIAL |  |
| `@pmndrs/pointer-events` | 6.6.30 | SAFE | ai | PARTIAL |  |
| `@posthog/types` | 1.412.2 | SAFE | ai | COMPLETE | fresh_publish |
| `@radix-ui/react-context` | 1.2.2 | SAFE | ai | PARTIAL |  |
| `@radix-ui/react-dismissable-layer` | 1.1.19 | SAFE | ai | COMPLETE |  |
| `@react-native-community/cli` | 20.2.0 | SAFE | ai | COMPLETE |  |
| `@react-pdf/paginate` | 1.0.1 | SAFE | ai | COMPLETE |  |
| `@react-pdf/render` | 4.7.0 | SAFE | ai | COMPLETE |  |
| `@react-spring/core` | 10.1.2 | SAFE | ai | COMPLETE |  |
| `@react-stately/flags` | 3.2.1 | SAFE | ai | COMPLETE |  |
| `@react-types/numberfield` | 3.9.0 | SAFE | ai | COMPLETE |  |
| `@react-types/select` | 3.13.0 | SAFE | ai | COMPLETE |  |
| `@rjsf/utils` | 6.10.1 | SAFE | ai | PARTIAL |  |
| `@rolldown/binding-linux-x64-musl` | 1.2.9 | SAFE | ai | PARTIAL |  |
| `@rspack/binding-win32-ia32-msvc` | 2.2.6 | SAFE | ai | PARTIAL |  |
| `@salesforce/b2c-cli` | 2.0.0 | SAFE | ai | COMPLETE | sandbox:eval_payload |
| `@sap/textbundle` | 6.3.0 | SAFE | ai | COMPLETE |  |
| `@sapphire/framework` | 5.5.1 | SAFE | ai | PARTIAL |  |
| `@sentry/cli-win32-arm64` | 3.8.0 | SAFE | ai | PARTIAL |  |
| `@slack/logger` | 5.0.0 | SAFE | ai | COMPLETE |  |
| `@specpow/framework` | 0.8.4 | SAFE | ai | PARTIAL | fresh_publish |
| `@stimulus-library/utilities` | 1.7.0 | SAFE | ai | PARTIAL |  |
| `@stripe/cli` | 1.51.0 | SAFE | ai | COMPLETE | install_script, fresh_publish |
| `@stripe/stripe-react-native` | 0.77.0 | SAFE | ai | PARTIAL | fresh_publish |
| `@sveltejs/adapter-node` | 5.5.7 | SAFE | ai | PARTIAL |  |
| `@tanstack/form-core` | 1.33.5 | SAFE | ai | COMPLETE |  |
| `@tanstack/react-router` | 1.170.38 | SAFE | ai | COMPLETE |  |
| `@tanstack/solid-store` | 0.11.1 | SAFE | ai | PARTIAL |  |
| `@tktco/node-actionlint` | 1.6.0 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `@trpc/next` | 11.19.0 | SAFE | ai | PARTIAL |  |
| `@tsed/common` | 8.38.7 | SAFE | ai | PARTIAL |  |
| `@types/cli` | 0.11.25 | SAFE | ai | COMPLETE |  |
| `@types/node-dijkstra` | 2.5.6 | SAFE | ai | COMPLETE |  |
| `@types/node-uuid` | 0.0.32 | SAFE | ai | COMPLETE |  |
| `@vue/cli-plugin-vuex` | 5.0.9 | SAFE | ai | COMPLETE |  |
| `@zhcsyncer/pi-tool-display-intent` | 0.10.0 | SAFE | ai | PARTIAL |  |
| `ag-charts-types` | 14.2.0 | SAFE | ai | COMPLETE |  |
| `ag-grid-community` | 36.2.0 | SAFE | ai | COMPLETE |  |
| `antlr-ng` | 1.0.10 | SAFE | ai | PARTIAL |  |
| `balena-semver` | 4.1.16 | SAFE | ai | COMPLETE |  |
| `component-inherit` | 0.0.3 | SAFE | ai | COMPLETE |  |
| `db-migrate` | 0.11.14 | SAFE | ai | COMPLETE | sandbox:decoy_read |
| `echarts-stat` | 1.2.0 | SAFE | ai | COMPLETE | new_publisher |
| `ember-cli-legacy-blueprints` | 0.2.1 | SAFE | ai | COMPLETE |  |
| `ember-cli-test-loader` | 3.1.0 | SAFE | ai | COMPLETE | new_publisher |
| `ember-cli-update` | 3.0.1 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `graphql-tag` | 2.12.7 | SAFE | ai | PARTIAL |  |
| `h264-profile-level-id` | 2.3.3 | SAFE | ai | COMPLETE |  |
| `has-async-hooks` | 1.0.0 | SAFE | ai | COMPLETE |  |
| `international-types` | 0.8.1 | SAFE | ai | COMPLETE |  |
| `iron-webcrypto` | 2.0.0 | SAFE | ai | COMPLETE |  |
| `isomorphic-fetch` | 3.0.0 | SAFE | ai | COMPLETE |  |
| `javascript-state-machine` | 3.1.0 | SAFE | ai | COMPLETE |  |
| `js-git` | 0.7.8 | SAFE | ai | COMPLETE |  |
| `json-cli-tool` | 2.0.7 | SAFE | ai | COMPLETE |  |
| `jss` | 10.10.0 | SAFE | ai | COMPLETE |  |
| `k` | 1.1.5 | SAFE | ai | COMPLETE |  |
| `keyname` | 0.1.0 | SAFE | ai | COMPLETE | new_publisher |
| `lambdatest-cypress-cli` | 3.0.50 | SAFE | ai | COMPLETE | sensitive_path |
| `map-or-similar` | 1.5.0 | SAFE | ai | COMPLETE |  |
| `markstream-core` | 2.0.12 | SAFE | ai | COMPLETE |  |
| `mdast-util-heading-range` | 4.0.0 | SAFE | ai | COMPLETE |  |
| `mdast-util-heading-style` | 3.0.0 | SAFE | ai | COMPLETE |  |
| `mdast-util-toc` | 7.1.0 | SAFE | ai | COMPLETE |  |
| `memoizerific` | 1.11.3 | SAFE | ai | COMPLETE |  |
| `my-node-fp` | 0.10.3 | SAFE | ai | COMPLETE |  |
| `nestjs-command` | 3.1.5 | SAFE | ai | PARTIAL |  |
| `nlcst-is-literal` | 3.0.0 | SAFE | ai | COMPLETE |  |
| `node-api-version` | 0.2.1 | SAFE | ai | COMPLETE |  |
| `node-bitmap` | 0.0.1 | SAFE | ai | COMPLETE |  |
| `node-cleanup` | 2.1.2 | SAFE | ai | COMPLETE |  |
| `node-jq` | 6.3.1 | SAFE | ai | COMPLETE | install_script |
| `node-range` | 0.1.0 | SAFE | ai | COMPLETE |  |
| `node-red-contrib-match` | 1.0.2 | SAFE | ai | COMPLETE |  |
| `node-red-contrib-message-counter` | 1.0.1 | SAFE | ai | PARTIAL |  |
| `node-zip` | 1.1.1 | SAFE | ai | COMPLETE |  |
| `numeric` | 1.2.6 | SAFE | ai | COMPLETE |  |
| `officecrypto-tool` | 0.0.19 | SAFE | ai | COMPLETE |  |
| `pegjs` | 0.10.0 | SAFE | ai | COMPLETE |  |
| `phantomwright-cli` | 2.3.0 | SAFE | ai | PARTIAL | sandbox:sandbox_detection, sensitive_path |
| `primeicons` | 8.0.1 | SAFE | ai | PARTIAL |  |
| `proper-lockfile` | 4.1.2 | SAFE | ai | COMPLETE |  |
| `prosemirror-trailing-node` | 3.0.0 | SAFE | ai | PARTIAL |  |
| `rc-drawer` | 7.3.0 | SAFE | ai | COMPLETE |  |
| `react-draggable` | 4.7.2 | SAFE | ai | PARTIAL |  |
| `react-ga` | 3.3.1 | SAFE | ai | PARTIAL |  |
| `react-native-web` | 0.21.2 | SAFE | ai | PARTIAL |  |
| `react-prop-types` | 0.4.0 | SAFE | ai | PARTIAL |  |
| `react-table` | 7.8.0 | SAFE | ai | PARTIAL |  |
| `react-use-measure` | 2.1.7 | SAFE | ai | PARTIAL |  |
| `recompose` | 0.30.0 | SAFE | ai | PARTIAL |  |
| `replicate` | 1.4.0 | SAFE | ai | COMPLETE |  |
| `rework` | 1.0.1 | SAFE | ai | COMPLETE |  |
| `smartapi-javascript` | 1.0.27 | SAFE | ai | COMPLETE |  |
| `socketcluster-client` | 20.0.2 | SAFE | ai | COMPLETE |  |
| `style-to-js` | 2.0.2 | SAFE | ai | COMPLETE |  |
| `style-to-object` | 2.0.2 | SAFE | ai | COMPLETE |  |
| `supabase` | 2.117.0 | SAFE | ai | COMPLETE |  |
| `svgi` | 1.1.2 | SAFE | ai | COMPLETE |  |
| `terser` | 5.51.2 | SAFE | ai | COMPLETE |  |
| `tfx-cli` | 0.24.2 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `unist-util-generated` | 3.0.0 | SAFE | ai | COMPLETE |  |
| `utf8` | 3.0.0 | SAFE | ai | COMPLETE |  |
| `vfile-statistics` | 3.0.0 | SAFE | ai | COMPLETE |  |
| `vite-plugin-node` | 8.0.0 | SAFE | ai | PARTIAL |  |
| `vscode-grammar-updater` | 1.1.0 | SAFE | ai | COMPLETE |  |
| `vue-metamorph` | 4.1.0 | SAFE | ai | PARTIAL |  |
| `watchpack` | 2.5.2 | SAFE | ai | COMPLETE |  |
| `windicss` | 3.5.6 | SAFE | ai | COMPLETE | sandbox:sandbox_detection |
| `xmlhttprequest-ssl` | 4.0.0 | SAFE | ai | COMPLETE |  |
| `yo` | 7.0.1 | SAFE | ai | PARTIAL | sandbox:decoy_read, sandbox:eval_payload, install_script |

## 5. Evaluation: legitimate but tricky packages (30)

Real packages that look suspicious to scanners: native builds, prebuilt-binary downloaders, install scripts. Expected SAFE.

| Package | Version | Verdict | Decided by | Sandbox | Key evidence |
|---|---|---|---|---|---|
| `gifsicle` | 7.0.1 | SUSPICIOUS | rules | COMPLETE | sandbox:dropper_exec, sandbox:decoy_read, install_script |
| `prisma` | 8.0.0-rc.15 | SUSPICIOUS | rules | PARTIAL | exfiltration |
| `@biomejs/biome` | 2.5.14 | SAFE | ai | COMPLETE |  |
| `@parcel/watcher` | 2.6.0 | SAFE | ai | COMPLETE | install_script, exec |
| `@prisma/client` | 7.10.0 | SAFE | ai | PARTIAL |  |
| `@tailwindcss/oxide` | 4.3.3 | SAFE | ai | COMPLETE |  |
| `argon2` | 0.45.1 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `chromedriver` | 153.0.2 | SAFE | ai | PARTIAL | install_script, fresh_publish |
| `cpu-features` | 0.0.10 | SAFE | ai | PARTIAL | install_script |
| `deasync` | 0.1.31 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script, exec |
| `esbuild-wasm` | 0.28.2 | SAFE | ai | COMPLETE |  |
| `geckodriver` | 6.1.1 | SAFE | ai | COMPLETE | install_script |
| `keytar` | 7.9.0 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `leveldown` | 6.1.1 | SAFE | ai | COMPLETE | install_script |
| `lightningcss` | 1.33.0 | SAFE | ai | COMPLETE |  |
| `msgpackr-extract` | 3.0.4 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `nan` | 2.29.0 | SAFE | ai | COMPLETE |  |
| `napi-postinstall` | 0.3.4 | SAFE | ai | COMPLETE |  |
| `node-addon-api` | 8.9.2 | SAFE | ai | COMPLETE |  |
| `node-pty` | 1.1.0 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `node-rdkafka` | 3.6.1 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `re2` | 1.26.1 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `robotjs` | 0.9.1 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `sass` | 1.104.1 | SAFE | ai | COMPLETE |  |
| `serialport` | 13.0.0 | SAFE | ai | COMPLETE |  |
| `ssh2` | 1.17.0 | SAFE | ai | COMPLETE | sandbox:suspicious_process, install_script, exec |
| `unrs-resolver` | 1.12.2 | SAFE | ai | COMPLETE | install_script |
| `usb` | 3.1.0 | SAFE | ai | COMPLETE |  |
| `utf-8-validate` | 6.0.6 | SAFE | ai | PARTIAL | sandbox:suspicious_process, install_script |
| `zeromq` | 6.8.0 | SAFE | ai | COMPLETE | install_script, exec |

## 6. Scanned by accident (lockfile upload) (30)

Real packages from a "Scan a project" lockfile upload on the website. 9 to 10 finished; 20 were stopped on purpose and are marked (stopped). Harmless and not part of any evaluation.

| Package | Version | Verdict | Decided by | Sandbox | Key evidence |
|---|---|---|---|---|---|
| `@alloc/quick-lru` | 5.3.0 | SAFE | ai | COMPLETE |  |
| `@apidevtools/json-schema-ref-parser` | 11.9.3 | SAFE | ai | COMPLETE |  |
| `@babel/code-frame` | 7.29.7 | SAFE | ai | COMPLETE |  |
| `@babel/compat-data` | 7.29.7 | SAFE | ai | PARTIAL |  |
| `@babel/core` | 7.29.7 | SAFE | ai | COMPLETE |  |
| `@babel/generator` | 7.29.8 | SAFE | ai | COMPLETE |  |
| `@babel/helper-annotate-as-pure` | 7.29.7 | SAFE | ai | COMPLETE |  |
| `@babel/helper-compilation-targets` | 7.29.7 | SAFE | ai | COMPLETE |  |
| `@babel/helper-create-class-features-plugin` | 7.29.7 | SAFE | ai | COMPLETE |  |
| `@babel/helper-module-transforms` | 7.29.7 | SAFE | ai | PARTIAL |  |
| `@babel/helper-globals` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-member-expression-to-functions` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-module-imports` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-optimise-call-expression` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-plugin-utils` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-replace-supers` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-skip-transparent-expression-wrappers` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-string-parser` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-validator-identifier` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helper-validator-option` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/helpers` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/parser` | 7.29.8 | (stopped) |  | not run |  |
| `@babel/plugin-syntax-jsx` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/plugin-syntax-typescript` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/plugin-transform-modules-commonjs` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/plugin-transform-typescript` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/preset-typescript` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/runtime` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/template` | 7.29.7 | (stopped) |  | not run |  |
| `@babel/traverse` | 7.29.8 | (stopped) |  | not run |  |
