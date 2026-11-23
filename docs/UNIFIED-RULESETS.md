# 统一 Surge 规则发布架构（试点：微信）

## 目标

所有受管理的规则通过本 GitHub 仓库审核、测试后发布，各设备只引用稳定版本。
每个服务保留一个规则集 URL，例如微信使用 `rules/WeChat.list`；
不同策略的内容仍必须分别放在各自的规则集，避免把 `REJECT` 和 `DIRECT` 混在同一个 `RULE-SET` 中。

## 微信试点

- `sources/blackmatrix7/WeChat.list`：blackmatrix7 原始微信规则快照。
- `sources/blackmatrix7/LICENSE`：上游 GPL-2.0 许可证副本。
- `custom/WeChat-CDN.list`：已在实验机验证的 4 个精确 CDN IP。
- `custom/WeChat-PCDN.list`：实测被广告规则拦截的微信 PCDN 域名；该域名已存在于上游微信规则，合并时去重。
- `scripts/build_wechat.py`：只从仓库内已审查快照生成统一规则集，不直接抓取最新网络内容。
- `rules/WeChat.list`：供将来设备引用的唯一微信规则文件（当前仅候选版本）。

**重要：Surge 采用从上到下的优先匹配。** 微信规则集必须在 `Advertising_All.list`、`Privacy_All.list`、`Hijacking.list`、`China_All.list` 和 `FINAL` 之前。
微信规则中的 `DOMAIN`、`IP-CIDR` 等只描述匹配条件，策略由外部引用处设置。
不支持在规则集内部通过嵌套 `RULE-SET` 来引用上游；此处生成的是扁平文件。

## 未来迁移示意（不要直接应用到现用设备）

先人工批准并发布固定 SHA（下方只是占位示例）：

```ini
[Rule]
RULE-SET,https://raw.githubusercontent.com/AutobotsRun/Surge-Rules/<REVIEWED_FULL_COMMIT_SHA>/rules/WeChat.list,"🚀 Direct",update-interval=86400
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising_All.list,REJECT
```

启用时原有的微信 `RULE-SET` 引用应由这**一条**替换，避免同一服务重复订阅；其他现有规则一律不触碰。
务必先在 iPhone 15 Pro 测试并确认微信视频、文字、图片和语音；用户明确授权之前，不修改任何设备。

## 审核及回滚

1. 检查上游提交内容与 GPL-2.0 授权/署名义务，人工提交上游快照更新 PR。
2. 在开发分支运行 `python3 scripts/build_wechat.py`，重新生成文件。
3. 用 `python3 scripts/build_wechat.py --check` 确认构建结果可重复、无意外变化。GitHub Actions 负责自动校验。
4. 审查整个 PR 的规则 diff、增删行数和风险，再由人工合并；**不自动合并、发布或写设备**。
5. 部署到实验机时记录旧 URL、旧版本 SHA 和规则位置。异常时恢复原配置/旧 SHA，完成验证再决定是否推广。
6. 长期规划：`rules/<Service>.list` 分别对应微信、Google、Netflix 等服务，`rules/Advertising.list` 对应 REJECT 类，`rules/China.list` 对应 DIRECT 类。各规则集策略独立且明确审查优先级。

## 当前边界

- 此阶段只有微信这一组完整统一规则候选；不能宣称其他 20 个规则集已经迁移。
- iPhone Air、Mac、iPhone 15 Pro 的正式 Surge 配置均保持原状；临时规则仍独立存在。
- 不在公开仓库提交节点、私密链接、API 密钥、WireGuard 配置或设备个人信息。
- 第三方规则不能未经许可核实就大规模复制；其他来源逐一审核。
