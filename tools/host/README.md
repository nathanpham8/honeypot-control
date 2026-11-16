# Host setup

`metadata-block.sh` and `honeypot-metadata-block.service` drop traffic from every container on the VM to the cloud metadata address 169.254.169.254, except DNS on port 53 (see `docs/swarm-pilot/step3-plan.md`, "Stage 1 review"). The unit re-inserts the rules every time Docker starts, so they survive reboots and Docker restarts.

Install (as root):

    install -m 0755 tools/host/metadata-block.sh /usr/local/sbin/honeypot-metadata-block.sh
    install -m 0644 tools/host/honeypot-metadata-block.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now honeypot-metadata-block.service

Check: `iptables -S DOCKER-USER` lists three rules with the comment `honeypot-control-metadata`.
