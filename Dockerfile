FROM python:3.13-slim

WORKDIR /app

COPY email_cleaner.py email_cleaner_watchdog.py ./

ENTRYPOINT ["python", "-u", "/app/email_cleaner.py"]
CMD ["--max-runtime-seconds", "3600", "--rules-file", "/data/rules.json", "--accounts-file", "/data/accounts.json", "--config-file", "/data/config.json", "--state-file", "/data/.email_cleaner_state.json"]
