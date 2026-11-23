# 八套服务规则镜像：审核、构建及发布说明

本批规则为 Google、YouTube、Apple、OpenAI、Telegram、Netflix、Spotify、HBO。它们均取自 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 的 Surge 规则集。上游仓库标注 GPL-2.0；仓库中的 `sources/blackmatrix7/LICENSE` 保留了许可证全文。

## 安全与许可

- `upstream/blackmatrix7/*.list` 保存已核实 SHA-256 的**原始上游快照**，不改变内容。
- `rules/<Service>.list` 是供 Surge 引用的独立规则集，仅在原始内容前增加标明上游、许可证和修改日期的来源头部。保留所有原始匹配规则及原顺序；不删除复合规则、CIDR、进程或 User-Agent 规则。
- 所有八份镜像的 `upstreams/catalog.json` 标记为人工审查通过的 `mode=mirror`，并保留 URL 和 GPL-2.0；其他上游继续保持 `mode=monitor`，尤其不镜像版权尚未确认的 Meta 来源。
- 因派生自 GPL-2.0 规则，规则快照及派生版本应继续遵循 GPL-2.0 的相关条件。不得去掉原始版权及署名说明。
- 不上传 Surge 完整配置、策略组、密钥或设备凭据；不能把这份规则集里的匹配条件理解成对应 `DIRECT` 或代理策略。

## 初始基线

| 服务 | 原始有效规则数量 | 自己的最终规则文件 |
| --- | ---: | --- |
| Google | 703 | `rules/Google.list` |
| YouTube | 190 | `rules/YouTube.list` |
| Apple | 1,615 | `rules/Apple.list` |
| OpenAI | 35 | `rules/OpenAI.list` |
| Telegram | 46 | `rules/Telegram.list` |
| Netflix | 1,158 | `rules/Netflix.list` |
| Spotify | 31 | `rules/Spotify.list` |
| HBO | 50 | `rules/HBO.list` |

规则的哈希值和大小另见 `upstreams/state.json`。每个文件的匹配策略应由 Surge 配置中的 `RULE-SET,<url>,<policy>` 指定，不允许把所有服务策略混在一起。

## 自动化工作流

1. `.github/workflows/audit-upstreams.yml` 在 `main` 上进行每日日检，拉取上游并校验来源与规模。
2. `scripts/audit_upstreams.py --sync` 更新八份已授权镜像及状态指纹，其余上游仅监控。
3. `scripts/build_service_rules.py --write` 从审核过的镜像生成八份服务规则列表。
4. CI 使用 `scripts/build_service_rules.py --check` 比对生成结果与发布文件，逐字节一致才算通过；镜像 SHA-256、字节数及规则数量也必须与状态文件一致。
5. 变更只创建草稿 PR，不自动合并或部署设备。修改服务清单、许可证、镜像路径、正则/复合规则或规则规模异常时要人工审查。

## 审核注意事项

- **Apple**：`Apple_All.list` 涵盖广泛域名和进程规则；修改策略可能影响苹果服务与推送。不要未经实验就改变 iPhone Air 或 Mac 的分流。
- **Telegram**：含原始 `OR` 复合 IP-ASN 规则，构建时必须原样保留。
- **HBO**：包含 `max.com`、`hbomax.com` 等域名、User-Agent 和进程规则；当前实验机沿用 `🇭🇰 HK`，不得因此调整其他策略顺序。
- **Netflix**：超过千条 IP-CIDR 规则，可能与其他服务规则和地理规则重叠；必须保留当前规则顺序。
- **Google / YouTube / OpenAI / Spotify**：部分域名或服务存在交集，不能未经测试自动去重或改变优先级。

## 设备测试与回滚

- 在 PR 审核通过前，所有新增 URL 都只是候选，不要指向设备。
- 合并后仍必须先使用**固定 commit SHA** 的 URL 在 iPhone 15 Pro 上逐条替换，原有策略和规则优先级保持不变。
- 先备份配置并记录旧 URL。出现功能异常时把实验机对应一条订阅恢复到旧 URL，而不是一次性替换所有服务。
- iPhone Air、Mac 及其他设备继续使用原配置，不因仓库合并自动切换。
