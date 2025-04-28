from collections import Counter

import numpy as np
import pandas as pd
from scapy.layers.inet import TCP
from scapy.utils import rdpcap
from scipy.stats import entropy

def calc_entropy(payload):
    """手动计算字节熵"""
    if not payload:
        return 0
    freq = Counter(bytes(payload))
    probs = [v/len(payload) for v in freq.values()]
    return -sum(p * np.log2(p) for p in probs if p > 0)

df = pd.read_csv('traffic.csv')
intervals = df['frame.time_relative'].diff().dropna()
print(f"心跳包平均间隔: {intervals.mean():.2f}s (±{intervals.std():.2f})")

packets = rdpcap('traffic.pcapng')
entropy_values = []
for p in packets:
    if p.haslayer(TCP) and p[TCP].payload:
        entropy_values.append(calc_entropy(p[TCP].payload))

print(f"平均熵值: {np.mean(entropy_values):.2f} bits")