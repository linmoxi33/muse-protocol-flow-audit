# muse-protocol-flow-audit

离线审计一份抓包得到的 muse.ai 注册/兑换会话：它是否真的符合 `duwqijlk/muse-protocol`
文档写下的步骤顺序、必填字段，以及**跨步动态值**的流转——confirm-otp 返回的 TOS 版本是否真的
被 register-completion 用上、bootstrap 文档里的披露文案是否真的被 accept-tos 用上。
为什么现在需要：上游 issue #3 的用户在 `register-completion` 拿到 400、issue #2 在激活拿到 403，
而仓库只提供一个“跑一遍才知道”的在线客户端，没有任何离线手段判断失败发生在哪一步、哪个字段。

Upstream: https://github.com/duwqijlk/muse-protocol

## 上游是什么、缺什么

`duwqijlk/muse-protocol`（1.5k★，MIT 之外的“仅供研究”声明）是一个纯 HTTP 复刻 muse.ai
注册与邀请码兑换流程的 Python 客户端。它把抓包逐字段比对得到的协议写进 README：12 步流程、
每步状态码，以及 6 个“容易踩的坑”。

它缺的是**对已捕获会话的机械判定**：

- issue [#3](https://github.com/duwqijlk/muse-protocol/issues/3)（open，👍1，2 条独立用户复现）
  报告人在 `register-completion` 收到
  `400: {"type":"invalidRequest","detail":"Check the account details and try again."}`，
  并给出了完整 5 步复现。正文只让“检查账号信息”，没人能离线判断是 DOB 触发 18 岁门、
  `tos_content_version` 与 confirm-otp 返回值不一致，还是姓名/字段缺失。
- issue [#2](https://github.com/duwqijlk/muse-protocol/issues/2)（open，4 条讨论）
  激活接口持续 403。README §4 已写明“必须先 bootstrap 再 accept-tos，否则后续 hatch 接口一律 403”，
  但没有工具检查一次会话里这个顺序与动态披露是否真的成立。
- 仓库自带的两个离线冒烟只覆盖 `parse_onboarding()` 纯函数
  （[`test_onboarding_smoke.py`](https://github.com/duwqijlk/muse-protocol/blob/main/test_onboarding_smoke.py)）
  与批量调度 mock
  （[`test_runner_smoke.py`](https://github.com/duwqijlk/muse-protocol/blob/main/test_runner_smoke.py)），
  没有 transcript / 状态机级校验。

## 这个工具做什么 / 不做什么

**做**：读一份本地 transcript（JSONL，或 JSON 数组），每条记录形如
`{"step": "...", "request": {"body": {...}}, "response": {"status": ..., "body": {...}}}`。
按上游 README 的 12 步顺序与 6 个坑做 15 条规则判定，输出可断言的 findings。

**不做**：不发任何网络请求；不替你注册；不重放流量；不绕过目标站点风控。
它只审计你已经捕获的会话数据。

## 安装 / 用法

零第三方依赖，Python 3.8+。

```bash
python3 muse_protocol_flow_audit.py examples/in/flow-clean.jsonl --today 2026-11-18
python3 muse_protocol_flow_audit.py examples/in/flow-broken.jsonl --json --today 2026-11-18
```

真实输出（`examples/out/` 由上面两条命令生成）：

- `flow-clean.jsonl` → `PASS (0 error / 0 warning / 0 info)`，exit 0
- `flow-broken.jsonl` → `FAIL (8 error / 1 warning)`，exit 1

`--json` 输出示例（截断）：

```json
{
  "tool": "muse-protocol-flow-audit",
  "upstream": "duwqijlk/muse-protocol",
  "fail_on": "error",
  "today": "2026-11-18",
  "summary": {"counts": {"error": 8, "warning": 1, "info": 0}, "triggered": 8, "status": "fail"},
  "findings": [
    {"rule": "TOS_VERSION_FLOW", "severity": "error", "index": 4, "step": "register_completion",
     "message": "register-completion sent a tos_content_version that differs from the one confirm-otp returned",
     "witness": {"confirm_otp": "...+docs_v2-OLD", "register_completion": "...+docs_v2"}}
  ]
}
```

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 没有达到 `--fail-on` 阈值的 finding |
| `1` | 至少一条 finding 达到/超过 `--fail-on`（默认 `error`） |
| `2` | 用法或输入错误（文件不存在、JSON 非法、`--today` 格式错误等） |

### 规则（15 条）

| 规则 | 级别 | 判定 |
|---|---|---|
| `FLOW_ORDER` | error | 步骤顺序偏离 README 的 12 步规范序 |
| `MISSING_STEP` | error | 缺失必需步骤（restart/send_otp/confirm_otp/register_completion/bootstrap/accept_tos/vm_wake/redeem） |
| `RESTART_BODY` | error | restart 请求缺 `resume` |
| `CONFIRM_OTP_FIELD` | error | confirm-otp 未带 `supports_muse_link_transparency: true` |
| `REGISTER_FIELDS` | error | register-completion 缺必填字段 |
| `DOB_FORMAT` | error | `date_of_birth` 非 `YYYY-MM-DD` |
| `DOB_AGE_GATE` | error | 生日推出年龄 < 18（上游文档：返回 403） |
| `TOS_VERSION_FLOW` | error | register-completion 的 `tos_content_version` ≠ confirm-otp 响应里的 `tos.content_version` |
| `ACCEPT_TOS_DYNAMIC` | error | accept-tos 缺 `disclosure_text` / `disclosure_version` |
| `ACCEPT_TOS_HARDCODED` | error | accept-tos 用了上游硬编码文案（README 要求用服务端动态文案） |
| `DISCLOSURE_VERSION` | error | `disclosure_version` ≠ `HATCH_ROW_v0` |
| `DISCLOSURE_FLOW` | error | accept-tos 的 `disclosure_text` ≠ bootstrap 文档解析值 |
| `DISCLOSURE_VERSION_FLOW` | error | accept-tos 的 `disclosure_version` ≠ bootstrap 文档解析值 |
| `VM_WAKE_BODY` | error | vm/wake 不是文档形态（`wake_trigger`/`away_ms`/`open_id`） |
| `STATUS_EXPECTATION` | error | 某步状态码不符合 README |
| `REDEEM_REASON` | warning | redeem reason 不在 `{redeemed,already_redeemed,used_up,invalid}` |
| `UNKNOWN_STEP` / `RECORD_NO_STEP` | warning/error | 未知步骤 / 记录缺 `step` |

## 与同类项目的差异

- `CoolkHz/muse-protocol-go`（75★）：Go SDK，负责“把请求发出去”，不做 transcript 审计。
- `HoshinoAz/museai-register`、`Selenium39/muse-auto-register`、`xyzww888/muse-JP-Reg`：
  注册脚本，只关心“能不能注册成功”，没有离线不变量校验。
- 通用 HTTP 录制回放（VCR 类）：只回放字节，不理解 muse 协议里的跨步动态值。

检索命令与完整命中见任务侧的 `similar.md`；没有 stars > 500 且功能覆盖的成熟同类。

## 本轮创新

首次把“非官方、靠抓包比对得出的协议”的**跨步动态值流转**做成可离线重放的会话审计：
它不是校验单条 payload 的静态字段，而是检查上一步响应里的 `tos.content_version` /
`disclosure_text` 是否真的流到了下一步请求——这正是 issue #3（400）与 #2（403）里用户
无法自证的那一层。上游与同类都只有“发请求的客户端”，没有“判定会话是否符合文档”的工具。

## 局限

- 输入 transcript 需要你自己捕获/整理成本工具的记录格式；它不是抓包代理。
- 只支持 `disclosureVersion == "HATCH_ROW_v0"`（与上游一致，未知版本不猜参数）。
- 状态码期望来自 README；站点升级后需要同步更新。
- 18 岁门是“约 18 年”的文档规则，用 `--today` 做确定性参考日；边界日可能有 ±1 天误差。
- 无法发现 transcript 里没有记录的问题（如 IP 级风控、TLS 指纹）。
- 本机禁止 `pip install`，上游客户端依赖 `curl_cffi`，因此没有跑上游在线客户端；规则全部
  来自 README 与 `musepy/client.py` 源码，并逐条对照实现。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

21 个用例（8 个走子进程的 CLI 行为用例 + 13 个规则用例），全部使用本地 fixture，离线可跑。