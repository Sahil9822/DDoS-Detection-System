from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
import math
import random
import os
from collections import Counter

app = Flask(__name__, template_folder='templates')
CORS(app)  # Enable Cross-Origin Resource Sharing

# Functions for DDoS Detection
def simulate_packet_flow(normal_traffic=1000, attack_traffic=500, attack=False):
    packets = [random.randint(1, 10) for _ in range(normal_traffic)]
    if attack:
        packets += [random.randint(1, 2) for _ in range(attack_traffic)]
    return packets

def calculate_entropy(packet_flow):
    packet_counts = Counter(packet_flow)
    total_packets = len(packet_flow)
    entropy = -sum((count / total_packets) * math.log2(count / total_packets) for count in packet_counts.values())
    return entropy

def detect_ddos(normal_entropy, current_entropy, threshold=0.5):
    deviation = abs(normal_entropy - current_entropy)
    return deviation > threshold

def calculate_accuracy(true_positive, false_positive, true_negative, false_negative):
    total = true_positive + false_positive + true_negative + false_negative
    return (true_positive + true_negative) / total * 100

# Baseline entropy for normal traffic
normal_packets = simulate_packet_flow(attack=False)
normal_entropy = calculate_entropy(normal_packets)

# Routes
@app.route('/')
def index():
    print("Templates directory:", os.path.join(os.getcwd(), "templates"))
    return render_template('index.html')

@app.route('/simulate', methods=['GET'])
def simulate_traffic():
    """
    Simulates traffic based on type ('normal' or 'attack').
    """
    traffic_type = request.args.get('type', 'normal')
    if traffic_type == 'attack':
        packets = simulate_packet_flow(attack=True)
    else:
        packets = simulate_packet_flow(attack=False)
    return jsonify({"packets": packets})

@app.route('/detect', methods=['POST'])
def detect_traffic():
    """
    Detects whether traffic represents a DDoS attack.
    """
    data = request.json
    packets = data.get('packets', [])
    if not packets:
        return jsonify({"error": "No packets provided"}), 400

    current_entropy = calculate_entropy(packets)
    is_attack = detect_ddos(normal_entropy, current_entropy)

    return jsonify({
        "normal_entropy": normal_entropy,
        "current_entropy": current_entropy,
        "ddos_detected": is_attack
    })

@app.route('/accuracy', methods=['POST'])
def check_accuracy():
    """
    Calculates the detection system's accuracy.
    """
    data = request.json
    true_positive = data.get('true_positive', 0)
    false_positive = data.get('false_positive', 0)
    true_negative = data.get('true_negative', 0)
    false_negative = data.get('false_negative', 0)

    accuracy = calculate_accuracy(true_positive, false_positive, true_negative, false_negative)
    return jsonify({"accuracy": f"{accuracy:.2f}%"})

if __name__ == '__main__':
    app.run(debug=True)
