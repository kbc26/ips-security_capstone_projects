from flask import Flask, jsonify
import json

app = Flask(__name__)

LOG_FILE = "/var/log/suricata/eve.json"

@app.route("/alerts")
def alerts():
    result = []

    with open(LOG_FILE, "r") as f:
        for line in f.readlines()[-200:]:
            data = json.loads(line)

            if data.get("event_type") == "alert":
                result.append({
                    "src": data["src_ip"],
                    "dst": data["dest_ip"],
                    "msg": data["alert"]["signature"]
                })

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
