#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
store_clauses_v2.py — 商店条款库升级：
1. 每条条款加 platform 字段（'ios' / 'android' / 'both'）
2. get_store_clauses(rtag, platform='ios') 按平台过滤
3. 定级规则收紧：静态未核实 ≠ 需整改——新三级制
4. 附法务判断标准 + 商店判断标准检查点清单（供文档交互）
"""
from collections import defaultdict

# rtag → [条款 dict]，dict 含 platform 字段
_STORE = defaultdict(list)

def _add(rtag, platform, source, clause, text, level):
    _STORE[rtag].append({'platform': platform, 'source': source, 'clause': clause, 'text': text, 'level': level})

# ============ Apple App Store（platform=ios） ============
_add('R1', 'ios', 'App Store Review Guidelines', '5.1.1(i)',
     '隐私政策必须明确指出 App 收集的数据、收集方式、所有用途；与第三方共享须获得明确许可且第三方提供等同保护。', 'fix')
_add('R2', 'ios', 'App Store Review Guidelines', '5.1.2(i)',
     'App 不得要求用户必须先启用系统功能（例如推送通知、定位服务、跟踪），然后才能访问 App 的功能和内容、使用 App 或收到现金或其他补偿（包括但不限于礼品卡和兑换码）。', 'reject')
_add('R2', 'ios', 'App Store Review Guidelines', '5.1.1(i)',
     '未经用户许可不得使用、传输或共享个人数据；须说明以何种方式在哪里使用这些数据。', 'reject')
_add('R3', 'ios', 'App Store Review Guidelines', '权限前置禁令',
     '权限请求不得作为功能访问前置条件。', 'reject')
_add('R4', 'ios', 'App Store Review Guidelines', '5.1.2 / 2.1 人脸申报',
     '使用非 LocalAuthentication 的人脸识别须申报：收集什么 face data / 用途 / 是否三方共享 / 存储位置 / 隐私政策原文引用。', 'fix')
_add('R4', 'ios', 'App Store Review Guidelines', '5.1.1(ii)',
     '为一个用途收集的数据未经用户额外同意不得用于其他用途。', 'fix')
_add('R5', 'ios', 'App Store Review Guidelines', '5.1.1(ii)',
     '未经额外同意，为一个用途收集的数据不可用于其他用途。', 'fix')
_add('R6', 'ios', 'App Store Review Guidelines', '5.1.1(i) 第三方保护',
     '与 App 共享用户数据的第三方（分析/广告/SDK）须提供与 App 隐私政策等同或更好的保护。', 'fix')
_add('R8', 'ios', 'App Store Review Guidelines', '5.1.1(i) ATT',
     '必须通过 App Tracking Transparency API 征得用户明确许可后才能追踪用户活动；未经 ATT 授权读取 IDFA 构成拒审。', 'reject')
_add('R9', 'ios', 'App Store Review Guidelines', '法律合规总则',
     'App 向某地区用户提供即须遵守该地区所有法律要求。', 'fix')

# ============ Google Play（platform=android） ============
_add('R1', 'android', 'Google Play User Data Policy', 'Data Safety 表单',
     'Data Safety 表单必须完整准确披露收集/使用/共享（含所有 SDK），且与隐私政策披露一致。', 'fix')
_add('R1', 'android', 'Google Play User Data Policy', 'Prominent Disclosure',
     '收集个人或敏感数据前必须提供 App 内醒目披露，格式："[App] collects/transmits/stores [数据类型] to enable [功能], [场景]"。', 'reject')
_add('R2', 'android', 'Google Play User Data Policy', '同意五要件',
     '同意必须满足：①清晰无歧义弹窗；②肯定动作；③导航离开不视为同意；④禁自动消失消息；⑤同意前不得开始收集或访问个人/敏感数据。', 'reject')
_add('R3', 'android', 'Google Play User Data Policy', 'User Data 最小化',
     '仅在个人/敏感数据与应用功能相关时才可传输到服务器。', 'fix')
_add('R3', 'android', 'Google Play User Data Policy', '受限权限',
     '受限权限和 API 只能在满足政策要求的场景下使用；背景位置等需额外声明。', 'fix')
_add('R5', 'android', 'Google Play User Data Policy', '受限权限/目的限制',
     '不得将权限获取的数据用于未披露、未实现或未经许可的功能或用途。', 'fix')
_add('R6', 'android', 'Google Play User Data Policy', 'SDK 连坐条款',
     '集成默认收集敏感数据的三方 SDK 须满足醒目披露与同意要求；Play 要求后 2 周内须提交证据。', 'fix')
_add('R7', 'android', 'Google Play Mobile Unwanted Software', 'MUW 政策',
     '应用不得在用户不知情或未同意的情况下收集/发送数据或后台运行。', 'fix')
_add('R8', 'android', 'Google Play Ads Policy', '广告 ID 政策',
     '使用广告 ID 须在隐私政策披露且仅限广告/分析用途。', 'fix')

# ============ 接口 ============

def get_store_clauses(rtag, platform='ios'):
    """按 R 维度取商店条款（platform='ios' 只返回 App Store 条款）"""
    all_c = _STORE.get(rtag, [])
    return [c for c in all_c if c['platform'] == platform or c['platform'] == 'both']

def render_store_bullets(rtag, platform='ios'):
    """渲染商店条款 bullet（HTML），按平台过滤"""
    out = []
    for c in get_store_clauses(rtag, platform):
        lvl = '🔴 拒审级' if c['level'] == 'reject' else '🟠 整改级'
        out.append(
            f"<li style='margin:6px 0;padding-left:2px'><b style='color:#3730a3'>{c['source']} · {c['clause']}</b>"
            f"<br><span style='color:#57606a'>{c['text']}</span> <span style='font-size:11px;color:{'#c9372c' if c['level']=='reject' else '#9a6700'}'>【{lvl}】</span></li>")
    return ''.join(out)

def get_store_redlines(platform='ios'):
    """商店红线清单（Reject 级判据），按平台"""
    RED = {
        'ios': [
            {'check': '同意前收集', 'criterion': '隐私弹窗点击前设备标识/敏感数据已发出（动态实测）', 'ref': '5.1.1(i)'},
            {'check': '权限前置', 'criterion': '必须授权（定位/相机等）才能使用核心功能', 'ref': '5.1.2(i)'},
            {'check': 'ATT 未授权追踪', 'criterion': 'iOS 14.5+ 未经 ATT 弹窗授权读取 IDFA/追踪', 'ref': '5.1.1(i) ATT'},
            {'check': '隐私政策缺失', 'criterion': 'App 内或商店元数据无可访问隐私政策链接', 'ref': '5.1.1(i)'},
            {'check': '暗中画像', 'criterion': '基于匿名数据重建用户身份/暗中构建用户资料', 'ref': '5.1.1(iii)'},
        ],
        'android': [
            {'check': '同意前收集', 'criterion': '同意弹窗点击前敏感数据已发出（动态实测）', 'ref': '同意五要件第⑤条'},
            {'check': '权限前置', 'criterion': '未同意先申请 runtime permission', 'ref': 'User Data / Prominent Disclosure'},
            {'check': '隐私政策缺失', 'criterion': 'Play Console 和 App 内均无隐私政策', 'ref': 'Privacy Policy'},
            {'check': 'Data Safety 不一致', 'criterion': '表单披露与实际收集不符', 'ref': 'Data Safety'},
            {'check': 'SDK 连坐违规', 'criterion': '集成默认收集 SDK 未披露未同意，2 周内无证据', 'ref': 'SDK 连坐条款'},
        ],
    }
    return RED.get(platform, [])

# ============ 定级规则（三级制，2026-10-27 收紧） ============
LEVELING_RULES = {
    'problem_found': {
        'label': '问题发现·需整改',
        'condition': '动态实测出事实（埋点/截图/流量三证至少其一）',
        'treatment': '直接写整改要求（不写"请验证"）',
    },
    'static_confirmed': {
        'label': '静态实锤·待运行时确认',
        'condition': '编译期确定性证据（二进制字符串/Ghidra 调用点）但未运行时验证',
        'treatment': '提供运行时核实路径（触发场景+验证方法）',
    },
    'suspected': {
        'label': '疑似·待核实',
        'condition': '静态推断，代码级证据查实，是否违规取决于运行时时序/披露',
        'treatment': '核实要点 + 验证方法',
    },
}

def get_leveling_rules():
    return LEVELING_RULES

if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    # 自检
    for pf in ['ios', 'android']:
        total = sum(len(get_store_clauses(f'R{i}', pf)) for i in range(1, 10))
        print(f'{pf}: {total} 条商店条款, {len(get_store_redlines(pf))} 项红线')
    print('定级规则:', list(LEVELING_RULES.keys()))
    # iOS 报告不应含 Google Play
    assert all('Google' not in c['source'] for c in get_store_clauses('R2', 'ios'))
    print('平台过滤验证 OK')
