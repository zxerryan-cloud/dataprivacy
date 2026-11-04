# QC 九项检查语义与 --fix 行为

`pipeline_quality_check.py <job_id> <report_id> [--fix]` 是流水线的质量门禁，九项全部 PASS（或仅 [4] WARN）才算交付。

| # | 检查项 | 语义 | --fix 行为 |
|---|--------|------|-----------|
| 1 | findings 完整性 | job 的 findings 覆盖 manifest/sdk/h5/const_string 各层，无空 job | 提示重跑 scan |
| 2 | SDK 粒度拆分 | Unknown/Other 类 SDK 按 entry_class 子包拆细（如 SankuaiCommon-Utils、Sailor-Camera、MtLive、MtMapSDK）；callgraph 与 sdk_section 包名一致 | 调 _fix_sdk_tab_granularity.py 自动拆分 |
| 3 | 启动触发链路 | 有敏感调用的 SDK 应有 startup_chain/chain_steps；前后端展示一致 | 从调用链证据回填 |
| 4 | first_party 拆分 | 一方 SDK 大桶（big catch-all buckets）应按功能拆分 | 拆分（历史欠账可能只到 WARN） |
| 5 | request_mapping/端点 | 每个 SDK 的上报端点（含动态端点标记 is_dynamic）与请求字段齐全；过滤 android.permission.* 噪声 | 按 entry_class/DESC 字典回填 |
| 6 | manifest 补全 | manifest 声明项（权限/组件/queries）有分析描述 | 调 _fix_manifest_desc.py + _sync_manifest_desc_job.py |
| 7 | manifest_section 前端真值（7b） | 直接校验 report.manifest_section——前端读的是 report 表，不是 findings 表；QC 必须以前端真实数据源为准 | 回写 report.manifest_section |
| 8 | JS Bridge 分析 | pipeline_jsbridge_check.py 已跑：JS API 作用/风险、穿透分析（H5→Native 敏感 API）、handler 宿主包归属（不在 Titans 框架包下也要能找到，如 GetWifiInfoJsHandler） | 调 pipeline_jsbridge_check.py 重跑 |
| 9 | native 组件清单 | sdk_section.native_components 有内容（磁盘 so + 动态下发 so、归属、启动加载、敏感特征） | 调 pipeline_native_scan.py 重扫 |

## 关键规则

1. **--fix 后必须复验**：`--fix` 跑完再跑一次不带 `--fix` 的 QC，九项状态才是最终结论
2. **QC 校验的是前端真值**：前端读 report 表的 manifest_section/sdk_section（不是 findings 表），QC 第 7 项直接查 report 表字段
3. **端点动态判定**：Horn 配置中心 `n.p(key, default)`、IRegionInfoService 区域端点、Retrofit baseUrl 注入 → is_dynamic=true；写死 URL → false。噪声域名（verify.meituan.com、*-eu.inf.st.keetapp.com 等 stage/dev/test）标 noise
4. **通过标准**：九项全 PASS；[4] first_party 若属历史大桶欠账可接受 WARN，但要在交付说明里写明
