// PkgGuard YARA rules: raw content patterns that don't depend on JavaScript structure.
// meta.capabilities marks what a match implies (used to combine signals per file).

rule discord_webhook
{
    meta:
        title = "Contains a Discord webhook URL (often used to send stolen data)"
        severity = "MEDIUM"
        confidence = "MEDIUM"
        capabilities = "network"
    strings:
        $url = /discord(app)?\.com\/api\/webhooks\/[0-9]+\// nocase
    condition:
        $url
}

rule telegram_bot_api
{
    meta:
        title = "Contains a Telegram bot API URL (often used to send stolen data)"
        severity = "MEDIUM"
        confidence = "MEDIUM"
        capabilities = "network"
    strings:
        $url = "api.telegram.org/bot" nocase
    condition:
        $url
}

rule request_capture_service
{
    meta:
        title = "Sends data to a request-capture or out-of-band testing service"
        severity = "HIGH"
        confidence = "MEDIUM"
        capabilities = "network"
    strings:
        $a = "webhook.site" nocase
        $b = ".pipedream.net" nocase
        $c = "oastify.com" nocase
        $d = "burpcollaborator.net" nocase
        $e = ".interact.sh" nocase
        $f = /\.oast\.(pro|live|site|online|fun|me)/ nocase
        $g = /requestbin\.(com|net|io|fullcontact\.com)/ nocase
        $h = "canarytokens.com" nocase
        $i = "dnslog.cn" nocase
        $j = "ceye.io" nocase
        $k = /ngrok(-free)?\.(io|app)/ nocase
        $l = "beeceptor.com" nocase
        $m = "requestcatcher.com" nocase
    condition:
        any of them
}

rule crypto_miner
{
    meta:
        title = "Contains cryptocurrency mining code"
        severity = "HIGH"
        confidence = "HIGH"
        capabilities = "network"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
        $c = "xmrig" nocase
        $d = "coinhive" nocase
        $e = "cryptonight" nocase
    condition:
        any of them
}

rule reverse_shell
{
    meta:
        title = "Contains a reverse shell (gives an attacker remote control)"
        severity = "HIGH"
        confidence = "HIGH"
        capabilities = "network,exec"
    strings:
        $a = /bash -i >& ?\/dev\/tcp\//
        $b = /\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\//
        $c = /nc(at)? [^\n]{0,60}-e \/bin\/(ba)?sh/
        $d = /\/bin\/(ba)?sh -i/
    condition:
        any of them
}

rule pipe_to_shell
{
    meta:
        title = "Downloads a script and pipes it straight into a shell"
        severity = "MEDIUM"
        confidence = "MEDIUM"
        capabilities = "network,exec"
    strings:
        $a = /(curl|wget) [^\n|;]{1,200}\| {0,5}(sudo +)?(ba|z)?sh/
    condition:
        $a
}

rule powershell_encoded
{
    meta:
        title = "Runs an encoded PowerShell command"
        severity = "HIGH"
        confidence = "MEDIUM"
        capabilities = "exec"
    strings:
        $a = /powershell[^\n]{0,80} -(e|enc|encodedcommand) / nocase
    condition:
        $a
}

rule javascript_obfuscator
{
    meta:
        title = "Code is heavily obfuscated (javascript-obfuscator style names)"
        severity = "MEDIUM"
        confidence = "MEDIUM"
        capabilities = ""
    strings:
        $name = /_0x[a-f0-9]{4,6}/
    condition:
        #name > 30
}

rule llm_prompt_injection
{
    meta:
        title = "Contains text aimed at AI code reviewers (prompt injection)"
        severity = "MEDIUM"
        confidence = "MEDIUM"
        capabilities = ""
    strings:
        $ignore = /ignore (all |any )?(the )?(previous|prior|above) instructions/ nocase
        $reviewer = /(ai|llm|gpt|claude|automated|security) (code )?(reviewer|scanner|auditor|analyzer|analyst)s?[^\n]{0,80}(safe|benign|not malicious|no issues)/ nocase
        $classify = /(mark|classify|report|treat) (this|the) (package|code|file|module) as (safe|benign|clean|trusted)/ nocase
    condition:
        any of them
}
