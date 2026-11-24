# Surge Rules

个人维护的 Surge 规则仓库：**上游审计 → 独立规则集 → 自动校验 → 草稿 PR → 人工审核 → 固定版本发布**。

这是公开仓库。请勿提交 Surge 完整配置、节点、账号、密钥、WireGuard/HTTP API 凭据或私人域名服务信息。

## 设备安全原则

- **iPhone 15 Pro 是唯一实验机**。其他 iPhone、iPhone Air 和 Mac 不自动切换新规则。
- GitHub Actions 只能提出草稿 PR，**没有自动合并、设备写入或部署步骤**。
- 规则集文件内只有匹配条件，Surge 中引用它的 `RULE-SET,<url>,<policy>` 才指定策略。
- 生产或稳定设备采用审核后的固定 Commit SHA 或稳定发布标签，不直接随 `main` 前移。

## 已发布的规则

| 规则文件 | 功能 | 状态 |
| --- | --- | --- |
| [rules/Advertising.list](rules/Advertising.list) | 审核过的黑矩阵广告规则，精准排除微信 PCDN 的一条误拦截 | 已发布，iPhone 15 Pro 用固定版本试运行 |
| [rules/WeChat.list](rules/WeChat.list) | 黑矩阵微信规则 + 四条自定义 CDN IP；规则去重 | 已发布，尚未切换实验机微信订阅 |
| [custom/WeChat-CDN.list](custom/WeChat-CDN.list) | 四条精确 CDN IP 例外 | 自定义源文件 |
| [custom/WeChat-PCDN.list](custom/WeChat-PCDN.list) | 微信 PCDN 域名例外 | 自定义源文件 |

## 精修规则发布候选（2026.11.24-rc1）

备用机实测规则的固定快照，**当前仍需审核，不自动部署**。

| 规则文件 | 数量 | 与已测试版的匹配条件差异 |
| --- | ---: | ---: |
| [Advertising-Lite.list](rules/Advertising-Lite.list) | 2,890 | 0 |
| [Privacy-Curated.list](rules/Privacy-Curated.list) | 39,935 | 0 |
| [Hijacking-Curated.list](rules/Hijacking-Curated.list) | 227 | 0 |

完整版 Advertising 保留。腾讯 Safe Browsing 继续拦截，Microsoft 继续现有直连策略；AdGuard Home 与 China_All 不变。发布审核完成后使用固定 SHA，先验收备用机，再由维护者手动共享正式配置。

详见 [发布与回滚](docs/CURATED-RULES-RELEASE.md)、[来源与许可证](docs/CURATED-RULES-NOTICES.md)、[固定版本清单](config/curated-rules-release.json)。

## 已审核的十六套服务规则

`Google`、`YouTube`、`Apple`、`OpenAI`、`Telegram`、`Netflix`、`Spotify`、`HBO`、`Amazon`、`Disney`、`ParamountPlus`、`Peacock`、`Reddit`、`PayPal`、`Sina`、`China_All` 分别发布为 `rules/<Service>.list`。这些文件保留上游全部匹配谓词及原有顺序，只加来源与修改说明；对应原始快照位于 `upstream/blackmatrix7/`。

前十五套已在 iPhone 15 Pro 切换到审核后的固定版本；China_All 先进行原样镜像验收，优先级修正另行审核。其他设备不动。

具体来源、GPL-2.0 许可、规则数量、自动构建和风险提示见 [十六套服务规则维护手册](docs/MANAGED-SERVICES.md)。

Meta AI 独立规则另见 [Meta AI 维护说明](docs/META-AI.md)。China_All 的优先级冲突及候选调整见 [China_All 审计](docs/CHINA-ALL-AUDIT.md)。

Garmin 独立候选规则见 [Garmin 实测与验收说明](docs/GARMIN.md)，不复制第三方规则集。

## 上游监测与同步

[upstreams/catalog.json](upstreams/catalog.json) 登记 21 个外部规则来源，[upstreams/state.json](upstreams/state.json) 保存审核过的 SHA-256、字节数和有效行数。

- `mode=monitor`：仅监测上游内容指纹，不在本仓库复制第三方规则。
- `mode=mirror`：仅经版权及来源审核的名单允许保存快照；构建生成规则集必须可重复、字节精确并有测试。
- 每日审计：`.github/workflows/audit-upstreams.yml`。只在 `main` 获取上游、对比后提出草稿 PR，**不自动合并**。
- 广告误拦截过滤：`.github/workflows/propose-advertising.yml`，只允许精准白名单并要求复杂规则指纹审核。
- `logicrw/RuleGo` 的 Meta 来源仍处于许可证未核实状态，只监测不镜像。

## 审核、测试与回滚

1. 查清实际分流/误拦截日志，再决定是否改变规则。
2. 检查许可证、原始快照 SHA-256、变更数量和规则类型。
3. 在候选 PR 上通过离线构建与 GitHub Actions 校验，不接受未经审核的新规则自动入库。
4. 手工合并后使用固定 SHA URL，在 iPhone 15 Pro 上逐条替换对应原始订阅；**不得额外叠加重复规则**。
5. 记录旧 URL 和旧策略；异常则实验机逐条回滚，其他设备继续保持原样。

相关手册：[规则审计与回滚](docs/OPERATIONS.md)、[微信统一规则](docs/UNIFIED-RULESETS.md)、[广告白名单](docs/ADVERTISING-EXCLUSIONS.md)。

原作者：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（GPL-2.0）与其他在 catalog 中注明的来源。
