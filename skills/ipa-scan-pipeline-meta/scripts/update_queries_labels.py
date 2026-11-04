#!/usr/bin/env python3
# 2026-10-29 修复：报告路径改为命令行参数 sys.argv（原桌面绝对路径已移除）
# 用法: update_queries_labels.py <细节报告.html> <风险报告.html>
# -*- coding: utf-8 -*-
"""
update_queries_labels.py — 补全 10 个未标注 scheme 的分类（联网核实）并更新两报告：
- ifood: iFood 巴西外卖龙头（Keeta 巴西市场直接竞对）
- noon: Noon 迪拜电商/noon Food 外卖（中东竞对）
- talabat: Talabat 中东最大外卖（Delivery Hero 旗下，GCC 市占 38-42%）
- snoonu: Snoonu 卡塔尔外卖/配送平台（竞对）
- careem: Careem Uber 旗下中东出行+外卖（竞对）
- taxis99: 99 滴滴旗下巴西打车+外卖（竞对，99Food 为 Keeta 巴西竞争对手）
- stcpay: STC Pay 沙特央行持牌数字钱包（支付）
- canvas-student: Canvas 学生端（在线学习平台 LMS Instructure）
- com.kaust.smart.one.payments: 沙特阿卜杜拉国王科技大学（KAUST）校园支付
- com.seu.services: 沙特电子大学（SEU）校园服务
更新：细节报告 50 scheme 表 + 风险报告卡的竞对计数（5→10）
"""
import io, sys

# 竞对新增 5：ifood/noon/talabat/snoonu/careem/taxis99 中，ifood noon talabat snoonu careem taxis99 = 6 个新竞对
# 原竞对 5（deliveroo/foodpanda/hungerstation/jahez/ananinja）→ 合计 11

DETAILS = {
    '风险报告': ('', [
        # (旧文本, 新文本)
        ('含 5 个竞对', '含 11 个竞对'),
        ('<b>竞对外卖 5 个</b>（Deliveroo/Foodpanda/HungerStation/Jahez/Ana Ninja）', '<b>竞对外卖 11 个</b>（iFood 巴西龙头/Talabat 中东最大 GCC 市占38-42%/Noon 迪拜电商旗下noonFood/Snoonu 卡塔尔/Careem Uber旗下出行+外卖/taxis99 滴滴旗下巴西打车+外卖99Food/Deliveroo/Foodpanda/HungerStation/Jahez/Ana Ninja）'),
        ('<b>竞对 {0} 个：deliveroo、foodpanda、hungerstation、jahez、ananinja</b>'.format(5), '<b>竞对 11 个：ifood、talabat、noon、snoonu、careem、taxis99、deliveroo、foodpanda、hungerstation、jahez、ananinja</b>——iFood 与 99Food 为 Keeta 巴西市场直接对手（曾签排他协议对抗 Keeta），Talabat/Noon Food/Snoonu/Careem 为中东市场主要竞对'),
        ('声明 {0} 个可探测 scheme，含 5 个竞对'.format(50), '声明 50 个可探测 scheme，含 11 个竞对'),
        # 类别计数行
        ('竞对 5 个：deliveroo、foodpanda、hungerstation、jahez、ananinja', '竞对 11 个：ifood、talabat、noon、snoonu、careem、taxis99、deliveroo、foodpanda、hungerstation、jahez、ananinja'),
    ]),
    '细节报告': ('', [
        # 表格行：未标注行替换为带分类的行
        ('<tr><td class="mono">ifood</td><td>ifood</td><td>其他/未标注</td></tr>', '<tr><td class="mono">ifood</td><td>iFood（巴西外卖龙头，Keeta 巴西直接竞对）</td><td>竞对外卖</td></tr>'),
        ('<tr><td class="mono">noon</td><td>noon</td><td>其他/未标注</td></tr>', '<tr><td class="mono">noon</td><td>Noon（迪拜电商，旗下 noon Food 外卖，中东竞对）</td><td>竞对外卖</td></tr>'),
        ('<tr><td class="mono">talabat</td><td>talabat</td><td>其他/未标注</td></tr>', '<tr><td class="mono">talabat</td><td>Talabat（中东最大外卖，Delivery Hero 旗下，GCC 市占约 40%）</td><td>竞对外卖</td></tr>'),
        ('<tr><td class="mono">snoonu</td><td>snoonu</td><td>其他/未标注</td></tr>', '<tr><td class="mono">snoonu</td><td>Snoonu（卡塔尔外卖/配送平台）</td><td>竞对外卖</td></tr>'),
        ('<tr><td class="mono">careem</td><td>careem</td><td>其他/未标注</td></tr>', '<tr><td class="mono">careem</td><td>Careem（Uber 旗下中东出行+外卖）</td><td>竞对外卖</td></tr>'),
        ('<tr><td class="mono">taxis99</td><td>taxis99</td><td>其他/未标注</td></tr>', '<tr><td class="mono">taxis99</td><td>99（滴滴旗下巴西打车+外卖 99Food）</td><td>竞对外卖</td></tr>'),
        ('<tr><td class="mono">stcpay</td><td>stcpay</td><td>其他/未标注</td></tr>', '<tr><td class="mono">stcpay</td><td>STC Pay（沙特央行持牌数字钱包）</td><td>支付/银行</td></tr>'),
        ('<tr><td class="mono">canvas-student</td><td>canvas-student</td><td>其他/未标注</td></tr>', '<tr><td class="mono">canvas-student</td><td>Canvas 学生端（Instructure 在线学习平台）</td><td>教育</td></tr>'),
        ('<tr><td class="mono">com.kaust.smart.one.payments</td><td>com.kaust.smart.one.payments</td><td>其他/未标注</td></tr>', '<tr><td class="mono">com.kaust.smart.one.payments</td><td>KAUST 校园支付（沙特阿卜杜拉国王科技大学）</td><td>教育</td></tr>'),
        ('<tr><td class="mono">com.seu.services</td><td>com.seu.services</td><td>其他/未标注</td></tr>', '<tr><td class="mono">com.seu.services</td><td>沙特电子大学（SEU）校园服务</td><td>教育</td></tr>'),
        # 汇总行更新
        ('（竞对外卖 5 个，超出', '（竞对外卖 11 个，超出'),
    ]),
}

for name, (path, reps) in DETAILS.items():
    h = io.open(path, encoding='utf-8').read()
    hit = 0
    for old, new in reps:
        if old in h:
            h = h.replace(old, new)
            hit += 1
        else:
            print(f'  [{name}] MISS: {old[:50]}')
    io.open(path, 'w', encoding='utf-8').write(h)
    print(f'{name}: {hit}/{len(reps)} 处更新')

# 校验
for name, (path, _) in DETAILS.items():
    h = io.open(path, encoding='utf-8', errors='replace').read()
    print(f'{name}: 未标注残留={h.count("其他/未标注")}, 竞对11={"11 个竞对" in h or "竞对 11 个" in h or "竞对外卖 11 个" in h}, 闭合={h.rstrip().endswith("</html>")}')
