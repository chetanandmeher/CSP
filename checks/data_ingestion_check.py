import json

with open(
    "data/mitre/enterprise-attack.json",
    "r",
    encoding="utf-8"
) as f:

    data = json.load(f)

count = 0

for obj in data["objects"]:

    if obj.get("type") == "attack-pattern":
        count += 1

print(count)