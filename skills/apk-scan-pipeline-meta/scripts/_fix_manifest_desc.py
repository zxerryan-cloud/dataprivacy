#!/usr/bin/env python3
"""自动分析并补充 Manifest 权限的描述、所属类、框架匹配、风险说明"""
import requests, json, re, os, sys

BASE = 'http://127.0.0.1:8791/rest/v1'
TOKEN = 'local-noauth'
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

HEADERS = {'apikey': TOKEN, 'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json'}

session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
session.mount('https://', HTTPAdapter(max_retries=retries))

def api_patch_finding(finding_id, patch):
    for attempt in range(3):
        try:
            r = session.patch(f'{BASE}/apk_scan_finding?id=eq.{finding_id}', headers=HEADERS, json=patch, timeout=60)
            return r.status_code in (200, 204)
        except Exception:
            if attempt == 2:
                return False
            import time; time.sleep(2)
JOB_ID = int(sys.argv[1]) if len(sys.argv) > 1 else 15
JAVA_SRC = sys.argv[2] if len(sys.argv) > 2 else 'sources'

# Android 标准权限知识库
PERMISSION_KNOWLEDGE = {
    # Android 标准权限
    'android.permission.INTERNET': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用打开网络套接字', 'risk': '低风险：网络访问是基础能力，但可用于数据上报'},
    'android.permission.ACCESS_NETWORK_STATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问网络状态信息', 'risk': '低风险：仅读取网络连接状态'},
    'android.permission.ACCESS_WIFI_STATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问Wi-Fi网络状态信息（SSID/BSSID等）', 'risk': '中风险：可获取WiFi SSID/BSSID用于定位'},
    'android.permission.CHANGE_WIFI_STATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用改变Wi-Fi连接状态', 'risk': '低风险：Wi-Fi开关控制'},
    'android.permission.WRITE_EXTERNAL_STORAGE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用写入外部存储', 'risk': '中风险：可读写用户文件'},
    'android.permission.READ_EXTERNAL_STORAGE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取外部存储', 'risk': '中风险：可读取用户文件'},
    'android.permission.CAMERA': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问摄像头', 'risk': '高风险：可采集图像/视频'},
    'android.permission.RECORD_AUDIO': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用录制音频', 'risk': '高风险：可采集麦克风音频'},
    'android.permission.ACCESS_FINE_LOCATION': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问精确位置（GPS）', 'risk': '高风险：精确位置采集'},
    'android.permission.ACCESS_COARSE_LOCATION': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问粗略位置（基站/WiFi）', 'risk': '中风险：粗略位置采集'},
    'android.permission.ACCESS_BACKGROUND_LOCATION': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用在后台访问位置', 'risk': '极高风险：后台持续位置追踪'},
    'android.permission.READ_PHONE_STATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取手机状态（IMEI/IMSI/设备ID等）', 'risk': '高风险：设备标识符采集'},
    'android.permission.READ_PHONE_NUMBERS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取手机号码', 'risk': '高风险：手机号采集'},
    'android.permission.CALL_PHONE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用拨打电话', 'risk': '高风险：可能产生费用'},
    'android.permission.READ_CONTACTS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取联系人', 'risk': '极高风险：通讯录采集'},
    'android.permission.WRITE_CONTACTS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用写入联系人', 'risk': '极高风险：修改通讯录'},
    'android.permission.READ_CALENDAR': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取日历', 'risk': '高风险：日程信息采集'},
    'android.permission.WRITE_CALENDAR': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用写入日历', 'risk': '高风险：修改日程'},
    'android.permission.SEND_SMS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用发送短信', 'risk': '极高风险：可能产生费用'},
    'android.permission.READ_SMS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取短信', 'risk': '极高风险：短信内容采集'},
    'android.permission.RECEIVE_SMS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用接收短信', 'risk': '极高风险：短信拦截'},
    'android.permission.BLUETOOTH': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用连接蓝牙设备', 'risk': '中风险：蓝牙设备扫描'},
    'android.permission.BLUETOOTH_ADMIN': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用发现和配对蓝牙设备', 'risk': '中风险：蓝牙设备管理'},
    'android.permission.BLUETOOTH_SCAN': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用扫描蓝牙设备（Android 12+）', 'risk': '中风险：蓝牙扫描可推断位置'},
    'android.permission.BLUETOOTH_CONNECT': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用连接已配对蓝牙设备（Android 12+）', 'risk': '低风险：已配对设备通信'},
    'android.permission.VIBRATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用控制振动器', 'risk': '低风险：仅振动反馈'},
    'android.permission.WAKE_LOCK': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用保持设备唤醒', 'risk': '低风险：保持屏幕/CPU唤醒'},
    'android.permission.RECEIVE_BOOT_COMPLETED': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用在系统启动完成后接收广播', 'risk': '中风险：开机自启动'},
    'android.permission.FOREGROUND_SERVICE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用启动前台服务', 'risk': '低风险：前台服务声明'},
    'android.permission.FOREGROUND_SERVICE_LOCATION': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许前台服务使用位置', 'risk': '高风险：前台位置服务'},
    'android.permission.FOREGROUND_SERVICE_CAMERA': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许前台服务使用摄像头', 'risk': '高风险：前台摄像头服务'},
    'android.permission.FOREGROUND_SERVICE_MICROPHONE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许前台服务使用麦克风', 'risk': '高风险：前台麦克风服务'},
    'android.permission.POST_NOTIFICATIONS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用发送通知（Android 13+）', 'risk': '低风险：通知推送'},
    'android.permission.SYSTEM_ALERT_WINDOW': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用在其他应用之上显示窗口', 'risk': '中风险：悬浮窗可能遮挡其他应用'},
    'android.permission.READ_MEDIA_IMAGES': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取媒体图片（Android 13+）', 'risk': '中风险：图片访问'},
    'android.permission.READ_MEDIA_VIDEO': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取媒体视频（Android 13+）', 'risk': '中风险：视频访问'},
    'android.permission.READ_MEDIA_AUDIO': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取媒体音频（Android 13+）', 'risk': '中风险：音频文件访问'},
    'android.permission.BODY_SENSORS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问身体传感器（心率/步数等）', 'risk': '高风险：健康数据采集'},
    'android.permission.ACTIVITY_RECOGNITION': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用识别身体活动（步行/跑步/骑车等）', 'risk': '高风险：身体活动识别'},
    'android.permission.SCHEDULE_EXACT_ALARM': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用设置精确闹钟', 'risk': '低风险：闹钟调度'},
    'android.permission.USE_BIOMETRIC': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用使用生物识别（指纹/面部）', 'risk': '中风险：生物识别认证'},
    'android.permission.USE_FINGERPRINT': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用使用指纹', 'risk': '中风险：指纹认证'},
    'android.permission.NFC': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用使用NFC', 'risk': '低风险：NFC通信'},
    'android.permission.REQUEST_INSTALL_PACKAGES': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用请求安装包', 'risk': '高风险：可能安装恶意应用'},
    'android.permission.QUERY_ALL_PACKAGES': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用查询所有已安装应用', 'risk': '高风险：应用列表采集'},
    'android.permission.HIGH_SAMPLING_RATE_SENSORS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问高采样率传感器', 'risk': '中风险：高频传感器数据'},
    'android.permission.ACCESS_NOTIFICATION_POLICY': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问通知策略', 'risk': '低风险：勿扰模式控制'},
    'android.permission.BROADCAST_STICKY': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用发送粘性广播', 'risk': '低风险：粘性广播'},
    'android.permission.FLASHLIGHT': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用控制闪光灯', 'risk': '低风险：闪光灯控制'},
    'android.permission.GET_TASKS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用获取正在运行的任务列表', 'risk': '中风险：可获取运行中的应用'},
    'android.permission.INTERACT_ACROSS_USERS_FULL': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用跨用户交互', 'risk': '高风险：跨用户操作'},
    'android.permission.MANAGE_ACCOUNTS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用管理账户', 'risk': '高风险：账户管理'},
    'android.permission.READ_SYNC_SETTINGS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取同步设置', 'risk': '低风险：同步设置读取'},
    'android.permission.WRITE_SYNC_SETTINGS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用写入同步设置', 'risk': '低风险：同步设置修改'},
    'android.permission.CHANGE_NETWORK_STATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用改变网络连接状态', 'risk': '低风险：网络开关控制'},
    'android.permission.MODIFY_AUDIO_SETTINGS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用修改音频设置', 'risk': '低风险：音频设置修改'},
    'android.permission.BILLING': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用使用应用内支付', 'risk': '中风险：支付相关'},
    'android.permission.READ_BASIC_PHONE_STATE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取基本手机状态（Android 12+）', 'risk': '中风险：基本设备信息'},
    # Google
    'com.google.android.gms.permission.AD_ID': {'class': 'Google', 'framework': 'Google Play Services', 'desc': '允许应用访问广告ID（GAID）', 'risk': '中风险：广告标识符采集，用于用户追踪'},
    'com.google.android.c2dm.permission.RECEIVE': {'class': 'Google', 'framework': 'Firebase Cloud Messaging', 'desc': '允许应用接收Firebase推送消息', 'risk': '低风险：推送消息接收'},
    'com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE': {'class': 'Google', 'framework': 'Google Play', 'desc': '允许应用获取安装来源信息', 'risk': '低风险：安装归因'},
    # Launcher 权限
    'com.android.launcher3.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': 'Android Launcher3', 'desc': '允许应用读取桌面设置', 'risk': '低风险：桌面布局读取'},
    'com.android.launcher3.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': 'Android Launcher3', 'desc': '允许应用写入桌面设置', 'risk': '低风险：桌面布局修改'},
    'com.htc.launcher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': 'HTC Launcher', 'desc': '允许应用读取HTC桌面设置', 'risk': '低风险：桌面布局读取'},
    'com.htc.launcher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': 'HTC Launcher', 'desc': '允许应用写入HTC桌面设置', 'risk': '低风险：桌面布局修改'},
    'com.qihoo360.launcher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': '360 Launcher', 'desc': '允许应用读取360桌面设置', 'risk': '低风险：桌面布局读取'},
    'com.qihoo360.launcher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': '360 Launcher', 'desc': '允许应用写入360桌面设置', 'risk': '低风险：桌面布局修改'},
    'net.qihoo.launcher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': '360 Launcher', 'desc': '允许应用读取360桌面设置', 'risk': '低风险：桌面布局读取'},
    'net.qihoo.launcher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': '360 Launcher', 'desc': '允许应用写入360桌面设置', 'risk': '低风险：桌面布局修改'},
    'com.tencent.qqlauncher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': 'QQ Launcher', 'desc': '允许应用读取QQ桌面设置', 'risk': '低风险：桌面布局读取'},
    'com.tencent.qqlauncher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': 'QQ Launcher', 'desc': '允许应用写入QQ桌面设置', 'risk': '低风险：桌面布局修改'},
    'org.adw.launcher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': 'ADW Launcher', 'desc': '允许应用读取ADW桌面设置', 'risk': '低风险：桌面布局读取'},
    'org.adw.launcher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': 'ADW Launcher', 'desc': '允许应用写入ADW桌面设置', 'risk': '低风险：桌面布局修改'},
    'com.anddoes.launcher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': 'Apex Launcher', 'desc': '允许应用读取Apex桌面设置', 'risk': '低风险：桌面布局读取'},
    'com.anddoes.launcher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': 'Apex Launcher', 'desc': '允许应用写入Apex桌面设置', 'risk': '低风险：桌面布局修改'},
    'com.huawei.android.launcher.permission.READ_SETTINGS': {'class': 'Launcher', 'framework': '华为 Launcher', 'desc': '允许应用读取华为桌面设置', 'risk': '低风险：桌面布局读取'},
    'com.huawei.android.launcher.permission.WRITE_SETTINGS': {'class': 'Launcher', 'framework': '华为 Launcher', 'desc': '允许应用写入华为桌面设置', 'risk': '低风险：桌面布局修改'},
    'com.huawei.permission.sec.MDM_PERMISSION': {'class': '华为', 'framework': '华为 MDM', 'desc': '华为移动设备管理权限', 'risk': '中风险：设备管理'},
    # 美团/点评
    'com.meituan.android.permissions.MIPUSH_RECEIVE': {'class': '美团', 'framework': '小米推送', 'desc': '允许应用接收小米推送消息', 'risk': '低风险：推送消息接收'},
    'com.dianping.android.permissions.MIPUSH_RECEIVE': {'class': '点评', 'framework': '小米推送', 'desc': '允许应用接收小米推送消息', 'risk': '低风险：推送消息接收'},
    'com.meituan.android.push.permission.NOTICE': {'class': '美团', 'framework': '美团推送', 'desc': '美团推送通知权限', 'risk': '低风险：推送通知'},
    'com.dianping.android.push.permission.NOTICE': {'class': '点评', 'framework': '点评推送', 'desc': '点评推送通知权限', 'risk': '低风险：推送通知'},
    # 小米
    'com.xiaomi.permission.SEND_PUSH_MESSAGE': {'class': '小米', 'framework': '小米推送', 'desc': '允许应用发送小米推送消息', 'risk': '低风险：推送消息发送'},
    # 华为推送
    'com.huawei.android.push.permission.RECEIVE': {'class': '华为', 'framework': '华为推送', 'desc': '允许应用接收华为推送消息', 'risk': '低风险：推送消息接收'},
    # 荣耀
    'com.hihonor.android.push.permission.RECEIVE': {'class': '荣耀', 'framework': '荣耀推送', 'desc': '允许应用接收荣耀推送消息', 'risk': '低风险：推送消息接收'},
    # Vivo
    'com.vivo.push.permission.RECEIVE': {'class': 'Vivo', 'framework': 'Vivo推送', 'desc': '允许应用接收Vivo推送消息', 'risk': '低风险：推送消息接收'},
    # Oppo
    'com.heytap.mcs.permission.RECEIVE': {'class': 'Oppo', 'framework': 'Oppo推送', 'desc': '允许应用接收Oppo推送消息', 'risk': '低风险：推送消息接收'},
    'com.coloros.mcs.permission.RECEIVE': {'class': 'Oppo', 'framework': 'Oppo推送', 'desc': '允许应用接收Oppo推送消息', 'risk': '低风险：推送消息接收'},
    # 其他常见
    'android.permission.DOWNLOAD_WITHOUT_NOTIFICATION': {'class': 'Android系统', 'framework': 'Android DownloadManager', 'desc': '允许应用无通知下载', 'risk': '中风险：静默下载'},
    'android.permission.EXPAND_STATUS_BAR': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用展开/收起状态栏', 'risk': '低风险：状态栏控制'},
    'android.permission.MOUNT_UNMOUNT_FILESYSTEMS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用挂载/卸载文件系统', 'risk': '高风险：文件系统操作'},
    'android.permission.READ_LOGS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用读取系统日志', 'risk': '高风险：日志可能含敏感信息'},
    'android.permission.SET_WALLPAPER': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用设置壁纸', 'risk': '低风险：壁纸设置'},
    'android.permission.SET_WALLPAPER_HINTS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用设置壁纸提示', 'risk': '低风险：壁纸提示'},
    'android.permission.ACCESS_LOCATION_EXTRA_COMMANDS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用访问额外的位置提供者命令', 'risk': '中风险：位置命令'},
    'android.permission.CHANGE_CONFIGURATION': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用改变配置', 'risk': '中风险：配置修改'},
    'android.permission.REORDER_TASKS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用重新排序任务', 'risk': '低风险：任务排序'},
    'android.permission.RESTART_PACKAGES': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用重启包', 'risk': '中风险：可能影响其他应用'},
    'android.permission.KILL_BACKGROUND_PROCESSES': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用杀死后台进程', 'risk': '中风险：影响其他应用'},
    'android.permission.GET_ACCOUNTS': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用获取账户列表', 'risk': '高风险：账户信息采集'},
    'android.permission.MANAGE_EXTERNAL_STORAGE': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用管理所有外部存储（Android 11+）', 'risk': '高风险：全文件访问'},
    'android.permission.SCHEDULE_EXACT_ALARM': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用设置精确闹钟', 'risk': '低风险：闹钟调度'},
    'android.permission.USE_FULL_SCREEN_INTENT': {'class': 'Android系统', 'framework': 'Android Framework', 'desc': '允许应用使用全屏意图', 'risk': '低风险：全屏通知'},
}

def analyze_permission(perm_name):
    """分析权限并返回描述信息"""
    # 先查知识库
    if perm_name in PERMISSION_KNOWLEDGE:
        info = PERMISSION_KNOWLEDGE[perm_name]
        return info['class'], info['framework'], info['desc'], info['risk']

    # 按前缀自动分类
    if perm_name.startswith('android.permission.'):
        suffix = perm_name.replace('android.permission.', '')
        return 'Android系统', 'Android Framework', f'Android系统权限：{suffix}', '需根据具体权限评估'
    elif perm_name.startswith('com.android.launcher') or 'launcher' in perm_name.lower():
        return 'Launcher', '第三方桌面', '桌面启动器权限', '低风险：桌面布局读写'
    elif perm_name.startswith('com.google.android'):
        return 'Google', 'Google Play Services', 'Google服务权限', '需根据具体权限评估'
    elif perm_name.startswith('com.huawei'):
        return '华为', '华为HMS', '华为服务权限', '需根据具体权限评估'
    elif perm_name.startswith('com.hihonor'):
        return '荣耀', '荣耀服务', '荣耀服务权限', '低风险：推送相关'
    elif perm_name.startswith('com.xiaomi') or perm_name.startswith('com.xiaomi'):
        return '小米', '小米服务', '小米服务权限', '低风险：推送相关'
    elif perm_name.startswith('com.vivo'):
        return 'Vivo', 'Vivo服务', 'Vivo服务权限', '低风险：推送相关'
    elif perm_name.startswith('com.heytap') or perm_name.startswith('com.coloros'):
        return 'Oppo', 'Oppo服务', 'Oppo服务权限', '低风险：推送相关'
    elif perm_name.startswith('com.meituan'):
        return '美团', '美团SDK', '美团自定义权限', '需根据具体权限评估'
    elif perm_name.startswith('com.dianping'):
        return '点评', '点评SDK', '点评自定义权限', '需根据具体权限评估'
    elif perm_name.startswith('com.sankuai'):
        return '美团', '美团SDK', '美团自定义权限', '需根据具体权限评估'
    elif perm_name.startswith('com.keetapp'):
        return 'Keeta', 'Keeta SDK', 'Keeta自定义权限', '需根据具体权限评估'
    elif perm_name.startswith('com.tencent'):
        return '腾讯', '腾讯SDK', '腾讯自定义权限', '需根据具体权限评估'
    elif perm_name.startswith('com.facebook'):
        return 'Facebook', 'Facebook SDK', 'Facebook自定义权限', '需根据具体权限评估'
    elif '.permission.' in perm_name:
        vendor = perm_name.split('.')[0] if '.' in perm_name else '未知'
        return vendor, '第三方SDK', f'{vendor}自定义权限', '需根据具体权限评估'
    else:
        return '自定义', '自定义权限', f'自定义权限：{perm_name}', '需人工评估'

# 获取所有 manifest findings
print(f"获取 job={JOB_ID} 的 manifest findings...")
r = session.get(f'{BASE}/apk_scan_finding?job_id=eq.{JOB_ID}&layer=eq.manifest&select=id,api_name,detail,severity,evidence&limit=5000', headers=HEADERS, timeout=120)
findings = r.json()
print(f"共 {len(findings)} 条")

# 分析并补充
patched = 0
for f in findings:
    perm_name = f.get('api_name', '')
    detail = f.get('detail')
    if isinstance(detail, str):
        try: detail = json.loads(detail)
        except: detail = {}
    if not isinstance(detail, dict):
        detail = {}

    # 检查是否已有描述
    has_info = detail.get('class_name') and detail.get('description')
    if has_info:
        continue

    # 自动分析
    cls, framework, desc, risk = analyze_permission(perm_name)

    detail['class_name'] = cls
    detail['framework_match'] = framework
    detail['description'] = desc
    detail['risk_note'] = risk

    if api_patch_finding(f['id'], {'detail': detail}):
        patched += 1

print(f"\n补充权限描述: {patched} 条")

# 也处理组件
print(f"\n获取组件 findings...")
r3 = session.get(f'{BASE}/apk_scan_finding?job_id=eq.{JOB_ID}&layer=eq.manifest&category=in.(组件-Activity,组件-Service,组件-Receiver,组件-Provider,queries-package)&select=id,api_name,detail,severity&limit=5000', headers=HEADERS, timeout=120)
comp_findings = r3.json()
print(f"共 {len(comp_findings)} 条组件")

comp_patched = 0
for f in comp_findings:
    comp_name = f.get('api_name', '')
    detail = f.get('detail')
    if isinstance(detail, str):
        try: detail = json.loads(detail)
        except: detail = {}
    if not isinstance(detail, dict):
        detail = {}

    if detail.get('description'):
        continue

    # 自动分析组件
    if comp_name.startswith('<queries><package>'):
        pkg = comp_name.replace('<queries><package>', '').replace('</package></queries>', '')
        detail['description'] = f'查询已安装应用：{pkg}（用于判断用户是否安装了该应用）'
        detail['risk_note'] = '中风险：应用列表探测'
        detail['class_name'] = 'queries-package'
    elif 'Activity' in f.get('category', ''):
        detail['description'] = f'Activity组件：{comp_name}'
        detail['risk_note'] = '低风险：界面组件'
    elif 'Service' in f.get('category', ''):
        detail['description'] = f'Service组件：{comp_name}'
        detail['risk_note'] = '中风险：后台服务'
    elif 'Receiver' in f.get('category', ''):
        detail['description'] = f'BroadcastReceiver组件：{comp_name}'
        detail['risk_note'] = '中风险：广播接收器'
    elif 'Provider' in f.get('category', ''):
        detail['description'] = f'ContentProvider组件：{comp_name}'
        detail['risk_note'] = '中风险：内容提供者'
    else:
        detail['description'] = f'组件：{comp_name}'
        detail['risk_note'] = '需人工评估'

    if api_patch_finding(f['id'], {'detail': detail}):
        comp_patched += 1

print(f"补充组件描述: {comp_patched} 条")
print(f"\n总计: 权限 {patched} + 组件 {comp_patched} = {patched + comp_patched} 条")
