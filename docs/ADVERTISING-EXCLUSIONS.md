# 去广告规则误拦截过滤机制（草稿）

## 为什么这样做

2026-11-23 实验机日志 #24035 显示 `apd-pcdnwxlogin.teg.tencent-cloud.net` 被原版 `Advertising_All.list` 拦截。微信原版规则其实也包含该域名，但在原有配置中广告规则排在微信之前。临时精确直连后，蜂窝与 Wi-Fi 均恢复正常，但不能证明全部卡顿均由该项造成。

目标是让自有广告规则集剔除该误拦截项，令微信无需长期依赖“优先于广告规则”这一特殊顺序。**这不意味着所有规则均不需要排序。**

## 工作流

1. `config/advertising-exclusions.json` 保存具体的放行域名、依据和审核标记。
2. GitHub Actions 从原版下载 `Advertising_All.list` 到临时文件。
3. `scripts/build_advertising.py` 严格按完整规则匹配，只删除 `DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net`，绝不按子串删除其他条目。
4. 必须恰好删除一条。如果找不到、重复、上游响应异常、文件过小或有可能继续覆盖域名的泛规则，则 **fail closed**（报错停止）。
5. 通过检查才生成候选 `rules/Advertising.list` 和新草稿 PR；**不自动合并、发布、修改设备或现有订阅**。
6. 每次更新由人工检查差异及许可证。确认 GitHub Actions 完整跑通后，再单独授权实验机使用固定版本，验证后逐步推广。

## 首次运行的限制

GitHub 仓库文件接口对上游这个大型列表没有返回完整正文。我们目前还**没有**验证它能生成候选输出。因为防误伤脚本将任何未经判定的 URL-REGEX / AND / OR 等复合规则视为风险，上游若存在这些规则，首次任务可能直接中止；这属于预期的保守保护，需人工审核后调整检测器，不能绕过校验直接发布。

仅发现独立 `DOMAIN` 条目并不能证明彻底消除拦截：DOMAIN-SUFFIX、DOMAIN-KEYWORD、DOMAIN-WILDCARD、正则、IP-CIDR 及其他规则仍可能命中。因此在实际部署后还必须用 Surge `match_rule` 验证并重复打开视频。

## 分支与合并

- 本分支基于微信统一规则的 PR #2 分支，只额外增加广告过滤相关机制。先审核 PR #2，再审核本 PR，避免重复合并其它功能。
- PR #1（通用来源审计）保持独立。
- 默认 `main` 和所有设备不受此次草稿影响。
- 许可：复制/改写 GPL-2.0 上游规则时保留对应署名和许可证；本分支沿用微信试点提交的 `sources/blackmatrix7/LICENSE`。

## 回滚

正式应用前，记录实验机原始广告规则订阅 URL、订阅顺序和固定提交 SHA。异常时恢复旧订阅，观察微信和广告拦截状态。仓库使用 Git revert 提交变更，不覆盖历史或强推主分支。


## 2026-11-23 上传文件的实际审查记录

用户提供的 `Advertising_All.txt` 是原始 Surge 规则纯文本，扩展名不影响解析。本地完整扫描结果：

- 原始文件：9,604,598 字节，SHA-256 `01f8b9caf1ab7b9ba58b17ebfcd04dc61b27af0751c43b5daa23ee5e7f6676d9`。
- 原始有效规则：291,174；DOMAIN 16,436；DOMAIN-SUFFIX 273,956；DOMAIN-KEYWORD 278；IP-CIDR 486；IP-CIDR6 3；URL-REGEX 14；AND 1。
- 第 4518 行恰好出现一次 `DOMAIN,apd-pcdnwxlogin.teg.tencent-cloud.net`。没有其它 `DOMAIN-SUFFIX` 或 `DOMAIN-KEYWORD` 覆盖该域名；已观察过的相关 PCDN IP 也没有命中现有 IP-CIDR 列表。
- 15 条复杂规则均予以保留，按原始顺序计算的 SHA-256 指纹为 `fe1ae9ca8060a098b242f2b4270c80ecdfb8d16d9d14711119184e5f88d4f23a`。更新时必须保持此集合不变，否则暂停并要求人工审查。
- 本地生成的候选 `Advertising.list`：291,173 条有效规则，即**仅减少 1 条 DOMAIN**；SHA-256 `ed3efe720f6ffa23b44e8923b3fa02091028f00e6cfcb3b40b94ab00e1ab52f7`。
- 现有 14 条 URL 正则中，有两条不限制域名、仅检查 URL 路径。它们并未随着域名排除而删除，因此不能保证任意路径均不会触发广告拦截；还必须在实验机用实际连接确认。单纯从规则集分析也无法保证未来新增 IP 规则不会影响该服务。
- GitHub 当前尚未生成/发布 `rules/Advertising.list`，以上 SHA 只对应本地审查的候选文件，不代表已在设备启用。构建程序的更新仍须通过 GitHub Actions 验证。
