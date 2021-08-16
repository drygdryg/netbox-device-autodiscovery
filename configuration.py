import toml

with open('configuration.toml') as f:
    config = toml.load(f)
