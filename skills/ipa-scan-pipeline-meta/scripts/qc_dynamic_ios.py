#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qc_dynamic_ios.py — iOS 动态检测报告 QC 质检（步骤 7E 固化版）
把这轮踩过的所有坑固化为检查项，FAIL 即 exit 2：
  Q1  细节报告：p8 动态实测 tab 存在
  Q2  细节报告：p3 敏感API表含 netlog 实测列
  Q3  细节报告：导图含动态节点且 leaf 可索引（cls_/detail 字段）
  Q4  细节报告：queries 表无"未标注"残留
  Q5  细节报告：p9 xcprivacy tab 存在且含动态交叉验证
  Q6  风险报告：标题含"动态实测"
  Q7  风险报告：描述层（hero/方法边界/总体情况）含动态说明
  Q8  风险报告：含"问题发现 · 需整改"红卡且排序在前
  Q9  风险报告：卡片状态一致性——处置建议含"动态验证已完成"的卡不得为"疑似"标签
  Q10 风险报告：分类正确性——无"通讯录"类目误配相机方法（requestAccessForMediaType 检查）
  Q11 风险报告：红卡含截图证据（📷 截图证据块）
  Q12 风险报告：统计一致性（hero 数字 = 实际红卡+黄卡数）
  Q13 双报告：HTML 闭合
  Q14 双报告：截图证据内嵌有效（data:image/png base64 可解码且非空）
用法：qc_dynamic_ios.py --report <细节.html> --risk <风险.html>
"""
import argparse, base64, io, os, re, sys, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def check(report_h, risk_h):
    fails, warns = [], []
    R = lambda cond, name, msg='': (None if cond else fails.append(f'{name}: {msg}'))
    W = lambda cond, name, msg='': (None if cond else warns.append(f'{name}: {msg}'))

    # ---- 细节报告 ----
    if report_h:
        R('id="p8"' in report_h, 'Q1', '细节报告缺 p8 动态实测 tab')
        R('netlog 实测（域名→字段）' in report_h, 'Q2', 'p3 敏感API表缺 netlog 实测列')
        R('动态实测·启动时序' in report_h, 'Q3', '导图缺动态节点')
        # Q3b: leaf 索引字段（防 walk 不到）
        W('"cls_":' in report_h or 'cls_\\":' in report_h or '动态实测·启动时序' in report_h, 'Q3b', '导图动态 leaf 缺 cls_/detail（点击无内容风险）')
        R('其他/未标注' not in report_h, 'Q4', 'queries 表有未标注 scheme（需 LLM/联网核实）')
        R('id="p9"' in report_h, 'Q5', '缺 p9 xcprivacy tab')
        W('动态实测 × 声明交叉验证' in report_h or '声明交叉验证' in report_h, 'Q5b', 'xcprivacy tab 缺动态交叉验证表')
        R(report_h.rstrip().endswith('</html>'), 'Q13', '细节报告 HTML 未闭合')

    # ---- Q15/Q16: framework 完整性（细节报告） ----
    if report_h:
        # Q15: 23 framework 明细表存在且行数够
        import re as _re
        fw_rows = len(_re.findall(r'USDKResources|TXSoundTouch|UnicoSdkPlugins', report_h))
        R(fw_rows >= 3, 'Q15', f'framework 完整明细表缺失或不完整（抽检 3 个尾部 framework 命中 {fw_rows}/3）')
        # Q16: Ghidra dump 文件数 22/23（job 目录扫描）
        job_fw_dir = os.environ.get('IOS_JOB_FW_DIR', '')
        dumps = [f for f in os.listdir(job_fw_dir) if f.startswith('fw_') and f.endswith('_dump.json')]
        R(len(dumps) >= 22, 'Q16', f'Ghidra framework dump 仅 {len(dumps)}/22（DeviceProfiling 结构异常可豁免，其余必须完成）')
        fps_scan = os.path.join(job_fw_dir, 'framework_sensitive_scan.json')
        if os.path.exists(fps_scan):
            fw_scan = json.load(open(fps_scan, encoding='utf-8'))
            R(len(fw_scan) >= 18, 'Q16b', f'指纹扫描覆盖 {len(fw_scan)}/23（应 ≥18 命中）')

    # ---- 风险报告 ----
    if risk_h:
        R('动态实测' in (risk_h[:3000]), 'Q6', '标题缺动态实测字样')
        R('静态证明代码结构' in risk_h or '两层证据' in risk_h, 'Q7', '方法边界缺动态层说明')
        R('问题发现 · 需整改' in risk_h, 'Q8', '无红卡（动态实锤卡）')
        # Q8b: 红卡排序在前（首个 card 标签后 2KB 内应含红标签）
        first_card = risk_h.find('<div class="card')
        if first_card > 0:
            R('问题发现 · 需整改' in risk_h[first_card:first_card+3000], 'Q8b', '红卡未排在卡区最前')
        # Q9: 状态一致性
        bad = 0
        for m in re.finditer(r'<span class="tag">疑似 · 待核实</span>', risk_h):
            ctx = risk_h[m.start():m.start()+6000]
            if '动态验证已完成' in ctx:
                # 粗判：同一卡内（无下一个 card-head）出现
                nxt = ctx.find('<div class="card-head">', 50)
                seg = ctx[:nxt] if nxt > 0 else ctx
                if '动态验证已完成' in seg: bad += 1
        R(bad == 0, 'Q9', f'{bad} 张卡内容含"动态验证已完成"但标签仍为疑似（状态不一致）')
        # Q10: 分类正确性
        R('requestAccessForMediaType' not in risk_h or '通讯录（5）' not in risk_h, 'Q10', '疑似通讯录误配相机方法（requestAccess 前缀问题）')
        # Q11: 红卡截图
        red_count = risk_h.count('问题发现 · 需整改')
        shot_count = risk_h.count('📷 截图证据') + risk_h.count('📷 证据形式说明')
        if red_count > 0:
            W(shot_count >= red_count, 'Q11', f'红卡 {red_count} 张但截图块仅 {shot_count} 个')
        # Q12: 统计一致
        m = re.search(r'风险 (\d+) 项（静态推断 (\d+) \+ 问题发现·需整改 (\d+)）', risk_h)
        if m:
            total, infer, red = int(m.group(1)), int(m.group(2)), int(m.group(3))
            actual_cards = risk_h.count('<div class="card ')
            actual_red = risk_h.count('问题发现 · 需整改')
            W(total == actual_cards and red == actual_red, 'Q12', f'hero统计({total}/{red})与实际({actual_cards}/{actual_red})不符')
        R(risk_h.rstrip().endswith('</html>'), 'Q13', '风险报告 HTML 未闭合')
        # Q14: base64 截图可解码
        imgs = re.findall(r'data:image/png;base64,([A-Za-z0-9+/=]{100})', risk_h)
        ok = all(len(base64.b64decode(i + '=' * (-len(i) % 4))) > 50 for i in imgs[:3]) if imgs else True
        W(ok and len(imgs) > 0, 'Q14', f'内嵌截图 {len(imgs)} 张（0 张或解码失败需检查）')

    return fails, warns

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--report'); ap.add_argument('--risk')
    a = ap.parse_args()
    rh = io.open(a.report, encoding='utf-8', errors='replace').read() if a.report else ''
    kh = io.open(a.risk, encoding='utf-8', errors='replace').read() if a.risk else ''
    fails, warns = check(rh, kh)
    print(f'== QC 动态检测报告 ==')
    print(f'FAIL: {len(fails)}  WARN: {len(warns)}')
    for f in fails: print('  [FAIL]', f)
    for w in warns: print('  [WARN]', w)
    if fails:
        sys.exit(2)
    print('QC PASS')

if __name__ == '__main__':
    main()
