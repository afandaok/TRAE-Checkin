#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Trae 每日签到脚本（GitHub Actions 版 · 对齐 traework 客户端请求）

已知事实（据此定位，勿再回到「限流洪峰」方向）：
  - 非整点定时、非整点手动执行，签到均失败 → 与时间无关，排除并发限流。
  - 只有官方 traework 客户端签到能成功。
  - traework 签到成功后，再跑脚本会出现「成功，本次获得 0 积分」——
    这不是脚本请求被放行的证据，而是当日已签到时 /claim 走了
    「已签到短路返回」分支，压根没进入真正发积分的逻辑。
  结论：脚本对「首次真实签到」始终是失败的，服务端把某类校验不通过
  统一伪装成「当前参与用户太多，请稍后再试」。

针对上述结论的改动：
  1. /claim 请求体必须是 {"req_source":2}，不能是 {}。
  2. User-Agent 改为与客户端一致：VSCode 1.107.1 (TRAE SOLO CN)。
  3. 补齐客户端指纹头：x-market-user-id / vscode-sessionid / x-device-* /
     x-app-version / x-lscbd-* / package-type / x-lgw-req-sdk-type /
     accept / accept-language / sec-fetch-* 等。
  4. x-user-region 改为大写 CN。
  5. 成功判定不再相信 /claim 的 code=0，必须以 /status 的 checked_in=true
     为准交叉验证（否则会被「假成功」误导）。
  6. 失败时打印完整 HTTP 状态与原始响应体，便于定位真正的 code。
  7. 保留少量退避重试，应对可能的瞬时错误。

未解决的上限：x-helios / x-medusa 是客户端反欺诈 SDK 的动态签名，Python 无法伪造。
若服务端强制校验这两个签名，纯脚本方案无法通关，最终手段见 README 说明。

原理：
  Trae 网页端 JWT 仅 8h 有效，真实会话凭证是 HttpOnly Cookie
  `X-Cloudide-Session`（约 14 天）。本脚本用该 Cookie 调 GetUserToken
  换全新 JWT，再用新 JWT 执行每日签到。

依赖：仅标准库。

环境变量（★ = 关键，必须配成 traework 抓包得到的真实值，缺失会派生假值并必然 9074）：
★ TRAE_DEVICE_ID        账号 1 的 x-device-id，如 45535852009417
★ TRAE_MARKET_USER_ID   账号 1 的 x-market-user-id，如 a15e2e30-80e5-43c5-8aa1-96bba5951415
★ TRAE_VSCODE_SESSIONID 账号 1 的 vscode-sessionid，64 位 hex
  TRAE_SESSION          账号 1 的 X-Cloudide-Session Cookie（必填）
  TRAE_DEVICE_BRAND     设备型号（选填，默认 90W2000WCP）
  TRAE_OS_VERSION       系统版本（选填，默认 Windows 11 Home China）
  TRAE_SESSION_N        第 N(N>=2) 个账号会话 Cookie；缺失即停止
  TRAE_DEVICE_ID_N / TRAE_MARKET_USER_ID_N / TRAE_VSCODE_SESSIONID_N
                        第 N 个账号对应的身份参数（多账号时每个都要各自抓包）
  TRAE_X_HELIOS / TRAE_X_MEDUSA
                        可选：抓包得到的动态签名，用于排查是否为必需项（可能过期）
  FEISHU_WEBHOOK        飞书机器人 webhook（选填，汇总推送）
  CHECKIN_JITTER_MAX    启动随机抖动上限（秒，默认 0 即关闭；设为>0启用）。
                        注：已排除整点洪峰假设，故默认关闭，仅作为可选去同步手段。
"""

import datetime
import hashlib
import json
import os
import random
import sys
import time
import urllib.request
import uuid

BASE = "https://api.trae.cn"

# 与 traework 客户端保持一致的应用/设备指纹常量
APP_VERSION = "0.1.67"
LSCBD_AID = "787976"
UA = "VSCode 1.107.1 (TRAE SOLO CN)"
NEPTUNE = "-11|50:51:59:00:09"  # 客户端日志中该值为固定常量


def derive_hex(seed, prefix, length):
    """由 session 派生稳定的十六进制串（同一账号跨运行保持一致）。"""
    h = hashlib.sha256((prefix + ":" + seed).encode("utf-8")).hexdigest()
    return h[:length]


def derive_uuid(seed, prefix):
    """由 session 派生稳定的 UUID（namespace 固定）。"""
    h = hashlib.sha1((prefix + ":" + seed).encode("utf-8")).digest()
    return str(uuid.UUID(bytes=h[:16]))


def derive_device_id(seed):
    """派生 14 位设备号（对齐客户端 45535852009417 的位数）。"""
    n = int(hashlib.sha1(("device:" + seed).encode("utf-8")).hexdigest(), 16)
    return str(n % 10 ** 14).zfill(14)


def _post(path, headers, body=""):
    """POST；非 2xx 不抛异常，以 (status, text) 返回，便于上层判断原因。"""
    import urllib.error
    req = urllib.request.Request(
        BASE + path, data=body.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def build_client_headers(token, identity):
    """构造与 traework 客户端一致的请求头。identity 含稳定指纹字段。"""
    headers = {
        "host": "api.trae.cn",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN",
        "authorization": "Cloud-IDE-JWT " + token,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-site": "none",
        "user-agent": UA,
        "vscode-sessionid": identity["vscode_sessionid"],
        "x-market-client-id": "VSCode 1.107.1",
        "x-market-user-id": identity["market_user_id"],
        "x-user-region": "CN",
        "content-type": "application/json",
        "x-app-version": APP_VERSION,
        "x-device-brand": identity["device_brand"],
        "x-device-id": identity["device_id"],
        "x-device-type": "windows",
        "x-lgw-req-sdk-type": "3",
        "x-os-version": identity.get("os_version") or "Windows 11 Home China",
        "package-type": "stable_cn",
        "x-request-id": str(uuid.uuid4()),
        "x-lscbd-aid": LSCBD_AID,
        "x-lscbd-platform": "windows",
        "app-version": APP_VERSION,
        "accept": "*/*",
        "x-tt-trace-id": "00-" + derive_hex(identity["device_id"], "trace", 32) + "-01",
        "x-neptune": NEPTUNE,
    }
    # 可选：若配置了抓包得到的动态签名则带上（用于排查签名是否为必需项）
    if identity.get("helios"):
        headers["x-helios"] = identity["helios"]
    if identity.get("medusa"):
        headers["x-medusa"] = identity["medusa"]
    return headers


def get_token(session: str) -> str:
    """用 X-Cloudide-Session Cookie 换取全新 JWT。"""
    headers = {
        "Cookie": "X-Cloudide-Session=" + session,
        "Referer": "https://www.trae.cn/",
        "Origin": "https://www.trae.cn",
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
    }
    status, text = _post("/cloudide/api/v3/common/GetUserToken", headers)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError("GetUserToken 返回非 JSON: %s" % text[:200])
    token = (data.get("Result") or {}).get("Token")
    if status == 401:
        raise RuntimeError(
            "账号会话已失效(HTTP 401)：X-Cloudide-Session 可能已过期(~14天)。"
            "请在浏览器重新登录 trae.cn 复制新 Cookie 更新到 TRAE_SESSION 后重试。"
            "原始返回: " + text[:200])
    if status != 200 or not token:
        raise RuntimeError("GetUserToken 失败: HTTP %s %s" % (status, text[:200]))
    return token


def checkin_status(token, identity) -> dict:
    """查询签到状态（对齐客户端先 status 再 claim 的流程）。"""
    headers = build_client_headers(token, identity)
    status, text = _post("/trae/api/v2/ug/checkin_credits/status", headers, '{"req_source":2}')
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text, "http": status}


def do_claim(token, identity) -> dict:
    """执行签到 claim，请求体为 {"req_source":2}（关键修复点）。"""
    headers = build_client_headers(token, identity)
    status, text = _post("/trae/api/v2/ug/checkin_credits/claim", headers, '{"req_source":2}')
    try:
        return {"http": status, "body": json.loads(text)}
    except json.JSONDecodeError:
        return {"http": status, "body": {"raw": text}}


# 命中这些文案/状态码时按「稍后重试」处理
RETRY_KEYWORDS = ["too many", "try again", "频繁", "稍后再试"]

# 确定性拦截码：重试无意义，应立刻失败，避免白白等待数分钟。
# 9074 实测结论：HTTP 200 + {"code":9074,"message":"当前参与用户太多，请稍后再试"}，
# 连续 5 次指数退避重试返回完全相同；非整点定时、非整点手动执行同样必然触发。
# 即：与时间和并发无关，是请求本身未通过服务端校验。文案「参与用户太多」是障眼法。
NO_RETRY_CODES = {9074}


def is_retryable(result) -> bool:
    http = result.get("http")
    body = result.get("body", {})
    if isinstance(body, dict) and body.get("raw"):
        return False
    msg = str((body or {}).get("message", "")).lower()
    code = (body or {}).get("code", 0)
    if code in NO_RETRY_CODES:
        return False
    if http in (429, 500, 502, 503, 504):
        return True
    if code != 0 and any(k in msg for k in RETRY_KEYWORDS):
        return True
    return False


def claim_with_retry(token, identity, max_retries=5):
    """带指数退避 + 抖动的签到；命中限流文案时重试。"""
    delay = 8
    last = None
    for attempt in range(1, max_retries + 1):
        last = do_claim(token, identity)
        body = last.get("body", {})
        code = body.get("code", -1) if isinstance(body, dict) else -1
        msg = (body.get("message", "") if isinstance(body, dict) else "")
        if last["http"] == 200 and code == 0:
            return last, attempt, True
        if not is_retryable(last):
            return last, attempt, False
        if attempt < max_retries:
            jitter = random.uniform(0.5, 1.5)
            wait = int(delay * jitter)
            print("  [限流] %s；第 %d/%d 次重试，%ds 后继续…"
                  % (msg, attempt, max_retries, wait))
            time.sleep(wait)
            delay = min(delay * 2, 120)
    return last, max_retries, False


def notify_feishu(webhook, text):
    if not webhook:
        return None
    try:
        payload = json.dumps({"msg_type": "text", "content": {"text": text}}).encode("utf-8")
        req = urllib.request.Request(
            webhook, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except Exception:
        return None


def beijing_now_str():
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def startup_jitter():
    """启动随机抖动：把同一 cron 分钟里同时启动的 runner 打散，避开抢签洪峰。

    已排除该假设，默认关闭（cap 默认 0），可用 CHECKIN_JITTER_MAX 显式开启。
    """
    raw = os.environ.get("CHECKIN_JITTER_MAX", "").strip()
    try:
        cap = int(raw) if raw else 0
    except ValueError:
        cap = 0
    if cap <= 0:
        return
    wait = random.uniform(0, cap)
    print("[调度] 随机抖动 %.0fs 后开始签到…" % wait)
    time.sleep(wait)


def iter_sessions():
    s = os.environ.get("TRAE_SESSION", "").strip()
    if s:
        yield 1, s, os.environ.get("TRAE_DEVICE_ID", "").strip()
    n = 2
    while True:
        s = os.environ.get("TRAE_SESSION_%d" % n, "").strip()
        if not s:
            break
        yield n, s, os.environ.get("TRAE_DEVICE_ID_%d" % n, "").strip()
        n += 1


def _acct_env(index, base):
    """读取账号级环境变量：账号1 读 BASE，账号N 优先读 BASE_N。"""
    if index <= 1:
        return os.environ.get(base, "").strip()
    return os.environ.get("%s_%d" % (base, index), "").strip()


def build_identity(index, session, device_id_override):
    """构造账号身份。

    重大结论：服务端是靠 x-market-user-id / x-device-id 这套「客户端设备身份」认账号的，
    JWT 并非关键（实测用打码的假 token 也能签到成功）。因此这里**绝不能**再派生假身份——
    派生的假 market-user-id / device_id 与真实账号不匹配，必然触发 code=9074。

    正确做法：用 reqable 抓取 traework 真实请求，把这三个值配到环境变量里。
    缺失时仍会派生，但会明确告警——派生值基本等于必然失败。
    """
    derived = []

    device_id = (_acct_env(index, "TRAE_DEVICE_ID") or device_id_override
                 or derive_device_id(session))
    if not (_acct_env(index, "TRAE_DEVICE_ID") or device_id_override):
        derived.append("TRAE_DEVICE_ID")

    market_user_id = (_acct_env(index, "TRAE_MARKET_USER_ID")
                      or derive_uuid(session, "market"))
    if not _acct_env(index, "TRAE_MARKET_USER_ID"):
        derived.append("TRAE_MARKET_USER_ID")

    vscode_sessionid = (_acct_env(index, "TRAE_VSCODE_SESSIONID")
                        or derive_hex(session, "vscode", 64))
    if not _acct_env(index, "TRAE_VSCODE_SESSIONID"):
        derived.append("TRAE_VSCODE_SESSIONID")

    device_brand = _acct_env(index, "TRAE_DEVICE_BRAND") or "90W2000WCP"
    os_version = _acct_env(index, "TRAE_OS_VERSION") or "Windows 11 Home China"

    if derived:
        print("[警告] 以下身份参数缺失，已使用派生假值，几乎必然触发 code=9074：%s"
              % "、".join(derived))
        print("[警告] 请用 reqable 抓取 traework 真实请求并配置这些环境变量。")

    return {
        "device_id": device_id,
        "market_user_id": market_user_id,
        "vscode_sessionid": vscode_sessionid,
        "device_brand": device_brand,
        "os_version": os_version,
        # 可选：动态反欺诈签名（回放自己抓包的值，可能过期，仅用于排查）
        "helios": _acct_env(index, "TRAE_X_HELIOS"),
        "medusa": _acct_env(index, "TRAE_X_MEDUSA"),
    }


def main():
    startup_jitter()

    accounts = list(iter_sessions())
    if not accounts:
        print("错误：缺少环境变量 TRAE_SESSION")
        sys.exit(1)

    webhook = os.environ.get("FEISHU_WEBHOOK", "").strip()
    ok_names, fail_names = [], []
    all_ok = True

    for index, session, device_id in accounts:
        name = "账号 %d" % index
        identity = build_identity(index, session, device_id)
        print("[%s] device_id=%s market_user_id=%s"
              % (name, identity["device_id"], identity["market_user_id"]))
        try:
            token = get_token(session)
            print("[%s] 已换取新 JWT，长度=%d" % (name, len(token)))

            # 先查状态：当日已签到则短路跳过（这正是「成功 0 积分」的来源）
            st = checkin_status(token, identity)
            if isinstance(st, dict) and (st.get("checked_in") or st.get("did_checked_in")):
                credits = st.get("credits", 0)
                print("[%s] 今日已签到（活动积分 %s），跳过" % (name, credits))
                ok_names.append(name)
                continue

            result, attempts, success = claim_with_retry(token, identity)
            body = result.get("body", {})
            if success:
                # 关键：不信 claim 的 code=0，必须拿 status 交叉验证才算真成功
                st2 = checkin_status(token, identity)
                confirmed = (isinstance(st2, dict)
                             and bool(st2.get("checked_in") or st2.get("did_checked_in")))
                if confirmed:
                    credits = st2.get("credits")
                    print("[%s] 签到成功（已核实 checked_in=true，第 %d 次请求通过，活动积分 %s）"
                          % (name, attempts, credits))
                    ok_names.append(name)
                else:
                    print("[%s] 疑似失败：/claim 返回成功，但 /status 未确认签到" % name)
                    print("[%s]   claim 原始响应: HTTP %s %s"
                          % (name, result["http"], json.dumps(body, ensure_ascii=False)[:300]))
                    print("[%s]   status 原始响应: %s"
                          % (name, json.dumps(st2, ensure_ascii=False)[:300]))
                    fail_names.append(name)
                    all_ok = False
            else:
                code = body.get("code") if isinstance(body, dict) else None
                msg = body.get("message") if isinstance(body, dict) else None
                print("[%s] 签到失败：code=%s message=%s" % (name, code, msg))
                print("[%s]   原始响应: HTTP %s %s"
                      % (name, result["http"], json.dumps(body, ensure_ascii=False)[:300]))
                if code == 9074:
                    print("[%s]   说明：9074 是确定性校验拦截，不是限流，重试无效。" % name)
                    print("[%s]   已对齐全部静态指纹后仍触发，剩余差异只剩 x-helios/x-medusa" % name)
                    print("[%s]   两个动态反欺诈签名 —— 纯 HTTP 复现路线到此为止。" % name)
                fail_names.append(name)
                all_ok = False
        except Exception as e:
            print("[%s] 签到异常: %s" % (name, e))
            fail_names.append(name)
            all_ok = False

    summary = ["Trae 多账号签到结果", "时间：%s" % beijing_now_str()]
    if ok_names:
        summary.append("成功：" + "、".join(ok_names))
    if fail_names:
        summary.append("失败：" + "、".join(fail_names))
    if webhook and (ok_names or fail_names):
        notify_feishu(webhook, "\n".join(summary))

    if not all_ok:
        sys.exit(1)
    print("全部账号签到完成")


if __name__ == "__main__":
    main()
