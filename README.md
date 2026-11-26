网络设备的授权查询只看了用户名，没看命令与服务，普通账号执行了配置级命令：授权判定必须同时校验用户、服务与命令；命令必须按参数逐个匹配；未知服务必须拒绝；会话必须绑定序号以防重放；响应必须校验签名；批量授权中每个请求相互独立。不变量是任何未显式授权的命令都被拒绝，同一会话序号不能复用。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 网络设备访问控制 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

## 请求

一次授权请求是字典，也可以通过 JSON 文本传入：

```python
{
    "session": "sess-1",
    "seq": 7,
    "user": "netops",
    "service": "shell",
    "cmd": "show",
    "args": ["version"],
    "signature": "<hmac-sha256 十六进制>",
    "now": 1000,
}
```

session 是非空字符串，seq 是从 1 开始的整数，user、service、cmd 是字符串，args 是字符串列表，signature 是六十四位小写十六进制。now 只用于会话过期判断，不参与签名。

## 策略

策略是由用户、服务、命令与签名要求组成的字典：

```python
{
    "users": {"allow": ["netops"], "deny": ["guest"]},
    "services": {"allow": ["shell", "exec"], "deny": ["tacacs"]},
    "commands": [
        {"cmd": "show", "args": ["version"], "allow": True},
        {"cmd": "show", "args": ["interface", "*"], "allow": True},
    ],
    "require_signature": True,
}
```

用户与服务按精确名称匹配，星号模式匹配任意名称；deny 列表优先于 allow 列表，没有命中 allow 的名称一律拒绝。命令规则中 cmd 按精确名称匹配，星号可以匹配任意命令名；args 必须与请求参数数量相同并逐个位置匹配，星号可以匹配该位置上的任意单个参数；只有 allow 为 True 的规则才能授予权限，找不到匹配规则时拒绝。

validate_policy 返回问题代码列表，可能包含 missing_command_rules、overbroad_wildcard 与 missing_signature。缺少命令维度、允许任意命令搭配任意参数、没有要求签名都属于策略问题，健康策略返回空列表。

## 签名

签名覆盖请求中的 session、seq、user、service、cmd、args 六个字段。将六个字段组成映射后，按字段名排序、分隔符为逗号与冒号、不含多余空格地序列化为 JSON，再以 UTF-8 编码。signature 是该字节串的 HMAC-SHA256，结果为六十四位小写十六进制。任一字段变化都必须使校验失败，缺失签名也必须失败。

## 会话

会话存储是以 sessions 为键的字典，每个会话对应一个条目，条目包含 seen 序号集合与 expires 过期时间。check_session 在序号首次出现时记录该序号并返回 True；同一会话中已经记录过的序号再次出现时返回 False。会话过期后可以重新建立。store 同时以 policy 键保存当前策略。

## 接口契约

- parse_request(raw) -> dict：接受字典或 JSON 文本，返回规范化的 session、seq、user、service、cmd、args、signature 字段；args 缺省为空列表。
- check_session(store, session, seq, now) -> bool：校验会话与序号，首次使用序号时记录并返回 True，重放已用序号返回 False。
- check_user(user, policy) -> bool：用户命中 allow 且未命中 deny 时为 True。
- check_service(service, policy) -> bool：服务命中 allow 且未命中 deny 时为 True，未知服务为 False。
- check_command(cmd, args, policy) -> bool：命令名与每个参数都匹配某条 allow 规则时为 True，否则为 False。
- verify_signature(request, key) -> bool：按约定重新计算 HMAC-SHA256 并与 signature 比较。
- validate_policy(policy) -> list[str]：返回策略问题代码列表，空列表表示没有问题。
- authz_batch(requests, store, key) -> dict：逐个处理请求，每个请求使用自己的会话与序号，单个请求失败不影响其他请求。

批量结果包含 results 与 allowed 两个键。results 与输入顺序一致，每项包含 session、seq、allowed 与 reasons；allowed 表示该请求是否通过，reasons 是失败原因代码列表，可能包含 signature、session、user、service 与 command。整体 allowed 仅在全部请求都通过时为 True。