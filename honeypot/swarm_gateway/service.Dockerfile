# Swarm pilot exit. Build context: the honeypot/ package directory, so the
# Experiment 3 gateway and collector are copied unchanged, not duplicated.
FROM python:3.12-slim
RUN pip install --no-cache-dir Flask==3.0.0
COPY gateway_server/app.py gateway_server/collector.py /app/
COPY swarm_gateway/swarm_exit.py swarm_gateway/swarm_sink.py swarm_gateway/swarm_forger.py swarm_gateway/forger_cold_template.json swarm_gateway/ctl.py /app/
COPY per_agent_containment.py gateway_summary.py /app/honeypot/
RUN touch /app/honeypot/__init__.py
WORKDIR /app
