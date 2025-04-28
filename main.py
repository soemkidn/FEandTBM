from collections import Counter

import numpy as np
import pandas as pd
from scapy.layers.inet import TCP
from scapy.utils import rdpcap
from scipy.stats import entropy
import matplotlib.pyplot as plt

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

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

# 图3a: 心跳间隔分布
ax1.hist(intervals, bins=15, edgecolor='k')
ax1.set_xlabel('Interval (s)'), ax1.set_ylabel('Frequency')

# 图3b: 熵值分布
ax2.hist(entropy_values, bins=20, color='orange', edgecolor='k')
ax2.set_xlabel('Entropy (bits)')
plt.savefig('features.png', dpi=300, bbox_inches='tight')