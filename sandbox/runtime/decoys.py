"""Plants fake credentials the package can find. Every value is random per run and unique, so a copy
of it in outbound traffic proves the package took it from here (see analyzer sandbox/canary.py)."""

import base64
import json
import os
import random
import string

ALNUM = string.ascii_letters + string.digits


def _rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(random.SystemRandom().choice(alphabet) for _ in range(n))


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def make_decoys(home: str) -> tuple[list[dict], list[dict]]:
    """Writes decoy files under `home`. Returns (files, env_vars): each with id, kind, value (the canary)."""
    files: list[dict] = []
    env: list[dict] = []

    def add_file(kind: str, rel: str, content: str, canary: str) -> None:
        path = os.path.join(home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        files.append({"id": f"{kind}", "kind": kind, "path": path, "value": canary})

    npm = "npm_" + _rand(36)
    add_file("npmrc", ".npmrc", f"//registry.npmjs.org/:_authToken={npm}\nregistry=https://registry.npmjs.org/\n", npm)

    key_body = [_b64(48) for _ in range(5)]
    add_file(
        "ssh_key", ".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(key_body) + "\n-----END OPENSSH PRIVATE KEY-----\n", key_body[1]
    )
    add_file("ssh_known_hosts", ".ssh/known_hosts", "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n", "github.com ssh-ed25519")
    files.pop()  # not a secret; kept only so ~/.ssh looks real
    os.makedirs(os.path.join(home, ".ssh"), mode=0o700, exist_ok=True)
    with open(os.path.join(home, ".ssh", "authorized_keys"), "w") as fh:
        fh.write("")

    akia = "AKIA" + _rand(16, string.ascii_uppercase + string.digits)
    aws_secret = _rand(40)
    add_file("aws_credentials", ".aws/credentials", f"[default]\naws_access_key_id = {akia}\naws_secret_access_key = {aws_secret}\n", aws_secret)

    dotenv_secret = "sk_live_" + _rand(24)
    add_file("dotenv", "project/.env", f"DATABASE_URL=postgres://app:{_rand(16)}@db.internal:5432/app\nSTRIPE_SECRET_KEY={dotenv_secret}\n", dotenv_secret)

    gh = "ghp_" + _rand(36)
    add_file("github_cli", ".config/gh/hosts.yml", f"github.com:\n  user: octocat\n  oauth_token: {gh}\n", gh)

    gcloud = _rand(40)
    add_file(
        "gcloud",
        ".config/gcloud/application_default_credentials.json",
        json.dumps({"type": "authorized_user", "client_id": _rand(12) + ".apps.googleusercontent.com", "client_secret": gcloud, "refresh_token": "1//" + _rand(60)}),
        gcloud,
    )

    docker_auth = base64.b64encode(f"deploy:{_rand(24)}".encode()).decode()
    add_file("docker", ".docker/config.json", json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": docker_auth}}}), docker_auth)

    kube = _rand(48)
    add_file("kube", ".kube/config", f"apiVersion: v1\nkind: Config\nusers:\n- name: admin\n  user:\n    token: {kube}\n", kube)

    hist = "export SECRET_TOKEN=" + _rand(32)
    add_file("shell_history", ".bash_history", f"ls\ncd project\n{hist}\nnpm publish\n", hist.split("=", 1)[1])

    chrome = _rand(28)
    add_file("browser_logins", ".config/google-chrome/Default/Login Data", "SQLite format 3\x00" + "\x00" * 16 + f"https://bank.example.com\x00user\x00{chrome}\x00", chrome)

    discord = _rand(24) + "." + _rand(6) + "." + _rand(27, ALNUM + "_-")
    add_file("discord_token", ".config/discord/Local Storage/leveldb/000005.ldb", f"\x00\x01token\x00{discord}\x00", discord)

    seed = " ".join(random.SystemRandom().choice(["apple", "river", "stone", "cloud", "lemon", "tiger", "mango", "ocean", "piano", "quartz", "eagle", "amber"]) for _ in range(12))
    add_file("crypto_wallet", ".config/Exodus/exodus.wallet/seed.seco", seed + "\n", seed)
    add_file("solana_keypair", ".config/solana/id.json", json.dumps([random.SystemRandom().randrange(256) for _ in range(64)]), "")
    files.pop()

    for name, value in (
        ("NPM_TOKEN", "npm_" + _rand(36)),
        ("GITHUB_TOKEN", "ghp_" + _rand(36)),
        ("AWS_ACCESS_KEY_ID", "AKIA" + _rand(16, string.ascii_uppercase + string.digits)),
        ("AWS_SECRET_ACCESS_KEY", _rand(40)),
        ("OPENAI_API_KEY", "sk-" + _rand(48)),
        ("DATABASE_URL", f"postgres://app:{_rand(16)}@db.internal:5432/app"),
    ):
        env.append({"id": f"env:{name}", "kind": "env", "name": name, "value": value})

    for rc in (".bashrc", ".profile", ".zshrc"):
        with open(os.path.join(home, rc), "w") as fh:
            fh.write("# ~/" + rc + "\nexport PATH=$HOME/.local/bin:$PATH\n")
    return files, env
