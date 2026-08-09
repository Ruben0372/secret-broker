import hashlib

SEP = chr(0x1F)  # matches the \u{1F} separator in DaemonBootstrap.digest(of:)


def digest(ns, name):
    return hashlib.sha256(f"{ns}{SEP}{name}".encode()).hexdigest()


target = digest("prod", "OPENAI_API_KEY")
print("observed receipt digest:", target)

namespaces = ["test", "prod", "dev", "staging", "default", "user", "armel"]
names = [
    "GITHUB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "SLACK_BOT_TOKEN",
    "OPENROUTER_API_KEY", "AWS_SECRET_ACCESS_KEY", "STRIPE_KEY", "DB_PASSWORD",
]

tries = 0
for ns in namespaces:
    for n in names:
        tries += 1
        if digest(ns, n) == target:
            print(f"RECOVERED after {tries} guesses: namespace={ns!r} name={n!r}")
            raise SystemExit(0)
print("not recovered")
