# Surge Rules

个人维护的 Surge 规则项目。**当前为实验阶段，不自动更改任何设备的 Surge 配置。**

## 原则

- iPhone 15 Pro 是唯一实验机；iPhone Air 与 M3 MacBook Pro 的稳定配置不自动同步。
- 保留上游规则的来源、许可证与独立更新渠道；变更先审查，再测试，最后才推广。
- 不上传 Surge 完整配置、代理节点、账号密码、WireGuard 密钥、HTTP API 密码或设备私有信息。
- 本仓库是 **Public**：所有提交内容对公众可见。

## 当前规则

| 文件 | 用途 | 状态 |
| --- | --- | --- |
| [custom/WeChat-CDN.list](custom/WeChat-CDN.list) | 纠正四个微信 CDN IP 的错误分流 | 四个 IP 已在 iPhone 15 Pro 临时规则中验证；远程订阅形式尚待测试 |

### 未来在 Surge 使用的方式（尚未启用）

以下只作说明，**未在设备启用，切勿直接将 `main` 当作稳定订阅版本**。将来测试时可将 URL 中的 `main` 替换为经过审核的固定提交 SHA，再将以下规则放在 `[Rule]` 中，且排在 `China_All.list`、`WeChat.list` 和 `FINAL` 之前：

```ini
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/main/custom/WeChat-CDN.list,"🚀 Direct",update-interval=86400
```

该 `RULE-SET` 文件只有匹配条件，策略 `🚀 Direct` 由配置中引用它的那一行指定。**不要把包含策略的临时规则原样复制到 .list 文件。**

> 目前实验机仍使用四条临时 IP 规则；本仓库不会自动替换这些规则。临时规则会随 Surge 引擎停止而消失。

## 上游规则管理（监测机制已进入待审核分支）

现阶段 **继续使用原作者的订阅 URL**，设备配置保持不变。已在待审核分支建立 21 个来源的只读清单和 GitHub Actions 审计框架。每天仅提出草稿 PR，人工批准后才更新仓库记录，不会自动更新设备；逐个确认许可证及署名义务后，才考虑镜像。

参考：

- [Surge 官方规则集说明](https://manual.nssurge.com/rules/ruleset.html)
- [Surge 官方域名匹配说明](https://manual.nssurge.com/rules/domain.html)
- [blackmatrix7 / ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)

## 变更流程

1. 基于日志和实际命中情况提出规则。
2. 优先在实验机用临时规则测试。
3. 确认效果后提交到仓库并检查格式、差异与冲突。
4. 在明确获得设备修改授权后，才调整实验机的正式配置。
5. 其他设备保持独立、手动升级。

详细流程：[来源监测、审批、发布与回滚手册](docs/OPERATIONS.md)。自动审计并不等于自动发布；`main` 只能由人工审阅合并更新。
