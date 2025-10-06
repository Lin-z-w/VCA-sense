import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# 创建数据
data = {
    'Protocol': ['TCP']*7 + ['QUIC']*7 + ['RTP']*7,
    'Forward_Loss_Set': [0, 1, 0, 1, 5, 1, 5, 0, 1, 0, 1, 5, 1, 5, 0, 1, 0, 1, 5, 1, 5],
    'Forward_Loss_Test': [0, 1.1104, 0.0387, 1.1415, 4.1411, 1.012, 4.3656, 0.0345, 0.99, 0, 0.9699, 4.2301, 0.9952, 4.3632, 0, 1.1022, 0, 0.8248, 2.7322, 0.7617, 3.2499],
    'Backward_Loss_Set': [0, 0, 1, 1, 5, 5, 1, 0, 0, 1, 1, 5, 5, 1, 0, 0, 1, 1, 5, 5, 1],
    'Backward_Loss_Test': [0, 0, 0.8906, 1.1851, 4.1174, 4.5437, 0.9272, 0, 0, 1.1153, 0.8786, 4.5808, 4.8119, 1.0139, 0, 0.2526, 1.1832, 2.0921, 5.9199, 6.0427, 1.7562]
}

df = pd.DataFrame(data)

# 提取设置值（由于所有协议在相同条件下测试，取TCP的设置值作为代表）
set_conditions = df[df['Protocol'] == 'TCP'][['Forward_Loss_Set', 'Backward_Loss_Set']].values
conditions_count = len(set_conditions)

# 设置图形
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

# 位置设置
x = np.arange(conditions_count)
width = 0.2

# colors = ['#FF0000', '#FFA500', '#FFD700', '#006400', '#0000FF', '#4B0082', '#800080']

# 颜色设置
colors = {
    'Set': '#FFD700',
    'TCP': '#FFA500', 
    'QUIC': '#4B0082',
    'RTP': '#800080'
}

# 前向丢包率柱状图
# 设置值
bars_set_f = ax1.bar(x - width*1.5, set_conditions[:, 0], width, 
                    label='Set Value', color=colors['Set'], alpha=0.8, 
                    edgecolor='black', linewidth=0.5)

# 各协议测试值
bars_tcp_f = ax1.bar(x - width/2, df[df['Protocol'] == 'TCP']['Forward_Loss_Test'], width,
                    label='TCP', color=colors['TCP'], alpha=0.8,
                    edgecolor='black', linewidth=0.5)

bars_quic_f = ax1.bar(x + width/2, df[df['Protocol'] == 'QUIC']['Forward_Loss_Test'], width,
                     label='QUIC', color=colors['QUIC'], alpha=0.8,
                     edgecolor='black', linewidth=0.5)

bars_rtp_f = ax1.bar(x + width*1.5, df[df['Protocol'] == 'RTP']['Forward_Loss_Test'], width,
                    label='RTP', color=colors['RTP'], alpha=0.8,
                    edgecolor='black', linewidth=0.5)

ax1.set_xlabel('Test Conditions', fontsize=12)
ax1.set_ylabel('Loss Rate (%)', fontsize=12)
ax1.set_title('Forward Packet Loss Comparison', fontsize=14, fontweight='bold')
ax1.legend(fontsize=10)
ax1.grid(True, alpha=0.3, axis='y')
ax1.set_xticks(x)
ax1.set_xticklabels([f'Cond {i+1}\n(F:{set_conditions[i,0]}%)' for i in range(conditions_count)])

# 后向丢包率柱状图
# 设置值
bars_set_b = ax2.bar(x - width*1.5, set_conditions[:, 1], width,
                    label='Set Value', color=colors['Set'], alpha=0.8,
                    edgecolor='black', linewidth=0.5)

# 各协议测试值
bars_tcp_b = ax2.bar(x - width/2, df[df['Protocol'] == 'TCP']['Backward_Loss_Test'], width,
                    label='TCP', color=colors['TCP'], alpha=0.8,
                    edgecolor='black', linewidth=0.5)

bars_quic_b = ax2.bar(x + width/2, df[df['Protocol'] == 'QUIC']['Backward_Loss_Test'], width,
                     label='QUIC', color=colors['QUIC'], alpha=0.8,
                     edgecolor='black', linewidth=0.5)

bars_rtp_b = ax2.bar(x + width*1.5, df[df['Protocol'] == 'RTP']['Backward_Loss_Test'], width,
                    label='RTP', color=colors['RTP'], alpha=0.8,
                    edgecolor='black', linewidth=0.5)

ax2.set_xlabel('Test Conditions', fontsize=12)
ax2.set_ylabel('Loss Rate (%)', fontsize=12)
ax2.set_title('Backward Packet Loss Comparison', fontsize=14, fontweight='bold')
ax2.legend(fontsize=10)
ax2.grid(True, alpha=0.3, axis='y')
ax2.set_xticks(x)
ax2.set_xticklabels([f'Cond {i+1}\n(B:{set_conditions[i,1]}%)' for i in range(conditions_count)])

plt.tight_layout()
plt.show()

# 显示测试条件说明
print("测试条件说明:")
for i, (fwd_set, bwd_set) in enumerate(set_conditions):
    print(f"条件 {i+1}: 前向设置丢包率 = {fwd_set}%, 后向设置丢包率 = {bwd_set}%")